// Package bittorrent provides a RouteWarden plugin for BitTorrent protocol inspection.
//
// It implements both sdk.Plugin (BitTorrent Peer Wire Protocol over TCP) and
// sdk.UDPPlugin (DHT + uTP over UDP), covering every layer of the BitTorrent
// transport stack.
//
// # Protocol Coverage
//
//	Transport  Protocol      BEP    Description
//	─────────  ────────────  ─────  ───────────────────────────────────────────
//	TCP        Peer Wire     3      Classic BT handshake + extension negotiation
//	UDP        DHT           5      Distributed Hash Table peer discovery
//	UDP        uTP           29     Micro Transport Protocol (LEDBAT congestion)
//
// # Capabilities
//
//   - Block / allow all BitTorrent traffic (TCP + UDP)
//   - Per-info-hash allow / deny lists (SHA-1 hex, case-insensitive)
//   - Block DHT peer discovery traffic independently
//   - Block uTP traffic independently
//   - Peer ID prefix allow/deny lists (block known bad clients; allow known good)
//   - Peer ID format enforcement (reject scanners that omit the -CCVVVV- prefix)
//   - DHT method allowlist / blocklist (e.g. block announce_peer to stop poisoning)
//   - DHT amplification protection via max response packet size
//   - Private-tracker mode: reject peers advertising DHT support in handshake
//   - Extension flag enforcement: require or forbid specific capability bits
//   - Detect and log extension flags from peer handshakes
//
// # Configuration
//
//	services:
//	  bittorrent:
//	    listen: ":6881"
//	    upstream: "backend:6881"
//	    transport: both          # bind TCP and UDP on :6881
//	    protocol: bittorrent
//	    udp:
//	      session_timeout: 60s
//	      max_sessions: 50000
//	    plugin_config:
//	      # ── Global posture ───────────────────────────────────────────────────
//	      mode: inspect           # "block" | "allow" | "inspect" (default)
//
//	      # ── Info hash filtering ───────────────────────────────────────────────
//	      blocked_info_hashes:
//	        - "aabbccddeeff00112233445566778899aabbccdd"
//	      allowed_info_hashes:    # if non-empty, only these hashes are forwarded
//	        - "1122334455667788990011223344556677889900"
//
//	      # ── Peer ID controls ─────────────────────────────────────────────────
//	      require_peer_id_format: true   # enforce "-CCVVVV-" prefix (rejects bots)
//	      blocked_peer_id_prefixes:      # block by 2-char Azureus-style client code
//	        - "-BS-"   # BitSpirit (known leecher)
//	        - "-UM-"   # µTorrent Mac (if policy requires)
//	      allowed_peer_id_prefixes:      # if non-empty = allowlist
//	        - "-qB-"   # qBittorrent
//	        - "-TR-"   # Transmission
//
//	      # ── Private-tracker / extension controls ──────────────────────────────
//	      private_tracker_mode: false    # reject peers with DHT extension bit set
//	      blocked_extensions:            # block peers advertising these extensions
//	        - "dht"        # DHT support (BEP 5)
//	        - "fast"       # Fast extension (BEP 6)
//	        - "extproto"   # Extension Protocol (BEP 10)
//	      required_extensions: []        # if non-empty, peers must advertise all of these
//
//	      # ── DHT controls ─────────────────────────────────────────────────────
//	      block_dht: false               # block all DHT traffic
//	      blocked_dht_methods:           # block specific DHT method names
//	        - "announce_peer"            # prevents DHT table poisoning
//	      allowed_dht_methods: []        # if non-empty = allowlist
//	      max_dht_packet_size: 1500      # amplification protection (0 = disabled)
//
//	      # ── uTP controls ─────────────────────────────────────────────────────
//	      block_utp: false               # block all uTP traffic
package bittorrent

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

//go:embed plugin.yaml
var manifestYAML []byte

func init() {
	plugins.Register(&BitTorrentPlugin{})
}

// BitTorrentPlugin implements sdk.Plugin (TCP Peer Wire) and sdk.UDPPlugin (DHT + uTP).
type BitTorrentPlugin struct{}

// Plugin is an alias for BitTorrentPlugin for consistency with modular plugin conventions.
type Plugin = BitTorrentPlugin

// ── Plugin options ────────────────────────────────────────────────────────────

type mode int

const (
	modeInspect mode = iota // emit events, forward (default)
	modeAllow               // forward silently
	modeBlock               // reject all BT traffic
)

// knownExtensionNames maps human-readable names to (byteIndex, bitMask) pairs
// in the 8-byte extension flags field of the BT handshake.
var knownExtensionNames = map[string][2]byte{
	"dht":      {7, extFlagDHT},
	"fast":     {7, extFlagFast},
	"extproto": {5, extFlagExtProto},
}

type btOptions struct {
	mode mode

	// Info hash filtering
	blockedInfoHashes map[string]struct{}
	allowedInfoHashes map[string]struct{}

	// Peer ID controls
	requirePeerIDFormat   bool
	blockedPeerIDPrefixes []string
	allowedPeerIDPrefixes []string // non-empty = allowlist

	// Private-tracker / extension controls
	privateTrackerMode bool
	blockedExtensions  [][2]byte // (byteIndex, bitMask) pairs
	requiredExtensions [][2]byte

	// DHT controls
	blockDHT          bool
	blockedDHTMethods map[string]struct{}
	allowedDHTMethods map[string]struct{} // non-empty = allowlist
	maxDHTPacketSize  int                 // 0 = disabled

	// uTP controls
	blockUTP bool
}

func parseOpts(config map[string]any) (btOptions, error) {
	opts := btOptions{
		blockedInfoHashes: make(map[string]struct{}),
		allowedInfoHashes: make(map[string]struct{}),
		blockedDHTMethods: make(map[string]struct{}),
		allowedDHTMethods: make(map[string]struct{}),
	}
	if config == nil {
		return opts, nil
	}

	// ── Global mode ───────────────────────────────────────────────────────────
	if v, ok := config["mode"].(string); ok {
		switch strings.ToLower(v) {
		case "block":
			opts.mode = modeBlock
		case "allow":
			opts.mode = modeAllow
		case "inspect", "":
			opts.mode = modeInspect
		default:
			return opts, fmt.Errorf("bittorrent: unknown mode %q (expected block|allow|inspect)", v)
		}
	}

	// ── Info hash lists ───────────────────────────────────────────────────────
	if err := parseHashList(config, "blocked_info_hashes", opts.blockedInfoHashes); err != nil {
		return opts, err
	}
	if err := parseHashList(config, "allowed_info_hashes", opts.allowedInfoHashes); err != nil {
		return opts, err
	}

	// ── Peer ID controls ──────────────────────────────────────────────────────
	if v, ok := config["require_peer_id_format"].(bool); ok {
		opts.requirePeerIDFormat = v
	}
	if err := parseStringList(config, "blocked_peer_id_prefixes", &opts.blockedPeerIDPrefixes); err != nil {
		return opts, err
	}
	if err := parseStringList(config, "allowed_peer_id_prefixes", &opts.allowedPeerIDPrefixes); err != nil {
		return opts, err
	}

	// ── Private-tracker / extension controls ──────────────────────────────────
	if v, ok := config["private_tracker_mode"].(bool); ok {
		opts.privateTrackerMode = v
	}
	if err := parseExtensionList(config, "blocked_extensions", &opts.blockedExtensions); err != nil {
		return opts, err
	}
	if err := parseExtensionList(config, "required_extensions", &opts.requiredExtensions); err != nil {
		return opts, err
	}

	// ── DHT controls ──────────────────────────────────────────────────────────
	if v, ok := config["block_dht"].(bool); ok {
		opts.blockDHT = v
	}
	if err := parseMethodSet(config, "blocked_dht_methods", opts.blockedDHTMethods); err != nil {
		return opts, err
	}
	if err := parseMethodSet(config, "allowed_dht_methods", opts.allowedDHTMethods); err != nil {
		return opts, err
	}
	if v, ok := config["max_dht_packet_size"].(int); ok {
		opts.maxDHTPacketSize = v
	} else if v, ok := config["max_dht_packet_size"].(float64); ok {
		opts.maxDHTPacketSize = int(v)
	}

	// ── uTP controls ──────────────────────────────────────────────────────────
	if v, ok := config["block_utp"].(bool); ok {
		opts.blockUTP = v
	}

	return opts, nil
}

// ── Option parsers ────────────────────────────────────────────────────────────

func parseHashList(config map[string]any, key string, dst map[string]struct{}) error {
	v, ok := config[key]
	if !ok {
		return nil
	}
	items := toStringSlice(v)
	if items == nil {
		return fmt.Errorf("bittorrent: %s must be a list of strings", key)
	}
	for _, s := range items {
		if err := validateInfoHash(s); err != nil {
			return fmt.Errorf("bittorrent: %s: %w", key, err)
		}
		dst[strings.ToLower(s)] = struct{}{}
	}
	return nil
}

func parseStringList(config map[string]any, key string, dst *[]string) error {
	v, ok := config[key]
	if !ok {
		return nil
	}
	items := toStringSlice(v)
	if items == nil {
		return fmt.Errorf("bittorrent: %s must be a list of strings", key)
	}
	*dst = items
	return nil
}

func parseMethodSet(config map[string]any, key string, dst map[string]struct{}) error {
	v, ok := config[key]
	if !ok {
		return nil
	}
	items := toStringSlice(v)
	if items == nil {
		return fmt.Errorf("bittorrent: %s must be a list of strings", key)
	}
	for _, s := range items {
		dst[strings.ToLower(s)] = struct{}{}
	}
	return nil
}

func parseExtensionList(config map[string]any, key string, dst *[][2]byte) error {
	v, ok := config[key]
	if !ok {
		return nil
	}
	items := toStringSlice(v)
	if items == nil {
		return fmt.Errorf("bittorrent: %s must be a list of extension names", key)
	}
	for _, name := range items {
		pair, ok := knownExtensionNames[strings.ToLower(name)]
		if !ok {
			return fmt.Errorf("bittorrent: %s: unknown extension %q (valid: dht, fast, extproto)", key, name)
		}
		*dst = append(*dst, pair)
	}
	return nil
}

func toStringSlice(v any) []string {
	if sl, ok := v.([]string); ok {
		return sl
	}
	if sl, ok := v.([]any); ok {
		out := make([]string, 0, len(sl))
		for _, item := range sl {
			s, ok := item.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	}
	return nil
}

func validateInfoHash(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("invalid hex info hash %q: %w", h, err)
	}
	if len(b) != 20 {
		return fmt.Errorf("info hash %q must be 20 bytes (40 hex chars), got %d bytes", h, len(b))
	}
	return nil
}

// ── Policy helpers ────────────────────────────────────────────────────────────

func (o *btOptions) isInfoHashAllowed(hexHash string) (bool, string) {
	hexHash = strings.ToLower(hexHash)
	if _, blocked := o.blockedInfoHashes[hexHash]; blocked {
		return false, fmt.Sprintf("bt_blocked_info_hash: %s", hexHash)
	}
	if len(o.allowedInfoHashes) > 0 {
		if _, ok := o.allowedInfoHashes[hexHash]; !ok {
			return false, fmt.Sprintf("bt_info_hash_not_allowlisted: %s", hexHash)
		}
	}
	return true, ""
}

// azureusRE matches the Azureus/BEP style peer ID: "-CCVVVV-XXXXXXXXXXXX"
// where CC is a 2-char client code and VVVV is a 4-char version string.
var azureusRE = regexp.MustCompile(`^-[A-Za-z]{2}[A-Za-z0-9]{4}-`)

func matchPeerIDPrefix(peerID, prefix string) bool {
	if strings.HasPrefix(peerID, prefix) {
		return true
	}
	// Support human-friendly "-CC-" prefix format (e.g. "-qB-", "-TR-", "-BS-")
	// for Azureus style peer IDs which are formatted as "-CCVVVV-".
	if len(prefix) == 4 && prefix[0] == '-' && prefix[3] == '-' {
		return strings.HasPrefix(peerID, prefix[:3])
	}
	return false
}

func (o *btOptions) isPeerIDAllowed(peerID string) (bool, string) {
	// 1. Format enforcement: must match Azureus-style "-CCVVVV-" prefix.
	if o.requirePeerIDFormat && !azureusRE.MatchString(peerID) {
		return false, fmt.Sprintf("bt_invalid_peer_id_format: %q", sanitisePeerID(peerID))
	}

	// 2. Blocked peer ID prefixes (e.g. "-BS-" for BitSpirit).
	for _, prefix := range o.blockedPeerIDPrefixes {
		if matchPeerIDPrefix(peerID, prefix) {
			return false, fmt.Sprintf("bt_blocked_peer_id_prefix: %s", prefix)
		}
	}

	// 3. Allowed peer ID prefixes (allowlist mode).
	if len(o.allowedPeerIDPrefixes) > 0 {
		matched := false
		for _, prefix := range o.allowedPeerIDPrefixes {
			if matchPeerIDPrefix(peerID, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			return false, fmt.Sprintf("bt_peer_id_prefix_not_allowlisted: %q", sanitisePeerID(peerID[:min(len(peerID), 8)]))
		}
	}

	return true, ""
}

func (o *btOptions) areExtensionsAllowed(flags [8]byte) (bool, string) {
	// Private-tracker mode: reject peers that advertise DHT support.
	if o.privateTrackerMode && (flags[7]&extFlagDHT != 0) {
		return false, "bt_private_tracker_dht_rejected"
	}

	// Blocked extensions: drop if peer advertises any of these.
	for _, pair := range o.blockedExtensions {
		if flags[pair[0]]&pair[1] != 0 {
			return false, fmt.Sprintf("bt_blocked_extension: byte%d/bit%02x", pair[0], pair[1])
		}
	}

	// Required extensions: drop if peer does NOT advertise all of these.
	for _, pair := range o.requiredExtensions {
		if flags[pair[0]]&pair[1] == 0 {
			return false, fmt.Sprintf("bt_missing_required_extension: byte%d/bit%02x", pair[0], pair[1])
		}
	}

	return true, ""
}

func (o *btOptions) isDHTMethodAllowed(method string) (bool, string) {
	method = strings.ToLower(method)
	if _, blocked := o.blockedDHTMethods[method]; blocked {
		return false, fmt.Sprintf("bt_dht_method_blocked: %s", method)
	}
	if len(o.allowedDHTMethods) > 0 {
		if _, ok := o.allowedDHTMethods[method]; !ok {
			return false, fmt.Sprintf("bt_dht_method_not_allowlisted: %s", method)
		}
	}
	return true, ""
}

// ── sdk.Plugin (TCP Peer Wire Protocol) ──────────────────────────────────────

func (p *BitTorrentPlugin) Manifest() sdk.Manifest {
	return sdk.MustParseManifest(manifestYAML)
}

func (p *BitTorrentPlugin) ValidateConfig(config map[string]any) error {
	_, err := parseOpts(config)
	return err
}

func (p *BitTorrentPlugin) SelfTest() error {
	hs := syntheticHandshake("aabbccddeeff00112233445566778899aabbccdd", "-RW0100-routewardentest")
	h, err := parseHandshake(hs)
	if err != nil {
		return fmt.Errorf("self-test handshake parse: %w", err)
	}
	if h.InfoHash != "aabbccddeeff00112233445566778899aabbccdd" {
		return fmt.Errorf("self-test: info hash mismatch: got %q", h.InfoHash)
	}
	return nil
}

func (p *BitTorrentPlugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	opts, err := parseOpts(config)
	if err != nil {
		return nil, err
	}
	return &btTCPInspector{opts: opts}, nil
}

// ── sdk.UDPPlugin (DHT + uTP) ─────────────────────────────────────────────────

func (p *BitTorrentPlugin) UDPManifest() sdk.Manifest {
	return sdk.MustParseManifest(manifestYAML)
}

func (p *BitTorrentPlugin) CreateUDPInspector(config map[string]any) (sdk.UDPInspector, error) {
	opts, err := parseOpts(config)
	if err != nil {
		return nil, err
	}
	return &btUDPInspector{opts: opts}, nil
}

// ── BitTorrent Peer Wire Protocol (TCP) ──────────────────────────────────────
//
// Handshake wire format:
//
//	Offset  Length  Field
//	──────  ──────  ─────────────────────────────────────────────
//	0       1       Protocol name length (always 19)
//	1       19      "BitTorrent protocol"
//	20      8       Extension flags (reserved bytes)
//	28      20      Info hash (SHA-1)
//	48      20      Peer ID (Azureus-style: -CCVVVV-XXXXXXXXXXXX)
//	Total:  68

type btHandshake struct {
	ExtensionFlags [8]byte
	InfoHash       string // lower-hex
	PeerID         string // raw 20 bytes as string
}

const (
	btHandshakeSize    = 68
	btProtocolName     = "\x13BitTorrent protocol"
	btProtocolNameSize = 20
)

// Extension flag positions (byteIndex, bitMask).
const (
	extFlagDHT      = byte(0x01) // byte 7, bit 0 — DHT (BEP 5)
	extFlagFast     = byte(0x04) // byte 7, bit 2 — Fast extension (BEP 6)
	extFlagExtProto = byte(0x10) // byte 5, bit 4 — Extension Protocol (BEP 10)
)

func parseHandshake(data []byte) (btHandshake, error) {
	if len(data) < btHandshakeSize {
		return btHandshake{}, fmt.Errorf("handshake too short: %d bytes (need %d)", len(data), btHandshakeSize)
	}
	if string(data[0:btProtocolNameSize]) != btProtocolName {
		return btHandshake{}, fmt.Errorf("not a BitTorrent handshake")
	}
	var h btHandshake
	copy(h.ExtensionFlags[:], data[20:28])
	h.InfoHash = hex.EncodeToString(data[28:48])
	h.PeerID = string(data[48:68])
	return h, nil
}

func isBitTorrentHandshake(data []byte) bool {
	return len(data) >= btHandshakeSize &&
		data[0] == 0x13 &&
		string(data[1:20]) == "BitTorrent protocol"
}

func describeExtensions(flags [8]byte) string {
	var exts []string
	if flags[7]&extFlagDHT != 0 {
		exts = append(exts, "DHT")
	}
	if flags[7]&extFlagFast != 0 {
		exts = append(exts, "Fast")
	}
	if flags[5]&extFlagExtProto != 0 {
		exts = append(exts, "ExtProto")
	}
	if len(exts) == 0 {
		return "none"
	}
	return strings.Join(exts, ",")
}

func syntheticHandshake(hexHash string, peerID string) []byte {
	buf := make([]byte, btHandshakeSize)
	copy(buf[0:btProtocolNameSize], btProtocolName)
	hashBytes, _ := hex.DecodeString(hexHash)
	copy(buf[28:48], hashBytes)
	pid := []byte(peerID + strings.Repeat("\x00", 20))
	copy(buf[48:68], pid[:20])
	return buf
}

func syntheticHandshakeWithFlags(hexHash, peerID string, flags [8]byte) []byte {
	buf := syntheticHandshake(hexHash, peerID)
	copy(buf[20:28], flags[:])
	return buf
}

// btTCPInspector applies the full peer-wire policy then proxies transparently.
type btTCPInspector struct {
	opts btOptions
}

func (i *btTCPInspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	var result sdk.ProxyResult

	client.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read exactly btHandshakeSize bytes from the client.
	buf := make([]byte, btHandshakeSize)
	n, err := io.ReadFull(client, buf)
	result.BytesIn = int64(n)
	if err != nil {
		return result, false, "", err
	}

	// Not a BT handshake — pass through transparently (e.g. HTTP on port 6881).
	if !isBitTorrentHandshake(buf) {
		written, err := upstream.Write(buf)
		result.BytesIn += int64(written)
		if err != nil {
			return result, false, "", err
		}
		client.SetDeadline(time.Time{})
		upstream.SetDeadline(time.Time{})
		res := protocol.Proxy(client, upstream)
		result.BytesIn += res.BytesIn
		result.BytesOut = res.BytesOut
		return result, false, "", res.Err
	}

	hs, err := parseHandshake(buf)
	if err != nil {
		return result, false, "", err
	}

	// ── 1. Global block mode ────────────────────────────────────────────────
	if i.opts.mode == modeBlock {
		ctx.OnSecurityEvent("blocked", "bt_blocked_by_policy")
		return result, true, "bt_blocked_by_policy", nil
	}

	// ── 2. Extension flag policy ────────────────────────────────────────────
	if ok, reason := i.opts.areExtensionsAllowed(hs.ExtensionFlags); !ok {
		ctx.OnSecurityEvent("blocked", reason)
		return result, true, reason, nil
	}

	// ── 3. Info hash policy ─────────────────────────────────────────────────
	if ok, reason := i.opts.isInfoHashAllowed(hs.InfoHash); !ok {
		ctx.OnSecurityEvent("blocked", reason)
		return result, true, reason, nil
	}

	// ── 4. Peer ID policy ───────────────────────────────────────────────────
	if ok, reason := i.opts.isPeerIDAllowed(hs.PeerID); !ok {
		ctx.OnSecurityEvent("blocked", reason)
		return result, true, reason, nil
	}

	// ── 5. Emit inspection event ────────────────────────────────────────────
	ctx.OnSecurityEvent("inspect", fmt.Sprintf(
		"bt_handshake: info_hash=%s extensions=%s peer_id=%q",
		hs.InfoHash, describeExtensions(hs.ExtensionFlags), sanitisePeerID(hs.PeerID),
	))

	// ── 6. Forward handshake and proxy remainder ────────────────────────────
	written, err := upstream.Write(buf)
	result.BytesIn += int64(written)
	if err != nil {
		return result, false, "", err
	}
	client.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})
	res := protocol.Proxy(client, upstream)
	result.BytesIn += res.BytesIn
	result.BytesOut = res.BytesOut
	return result, false, "", res.Err
}

func sanitisePeerID(id string) string {
	out := make([]byte, len(id))
	for i, b := range []byte(id) {
		if b >= 0x20 && b < 0x7f {
			out[i] = b
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── DHT protocol (UDP, BEP 5) ────────────────────────────────────────────────

func isDHTMessage(data []byte) bool {
	return len(data) >= 8 && data[0] == 'd' && data[len(data)-1] == 'e'
}

func extractDHTMessageType(data []byte) (msgType, methodName string) {
	s := string(data)
	idx := strings.Index(s, "1:y1:")
	if idx < 0 {
		return "", ""
	}
	if idx+6 <= len(s) {
		msgType = string(s[idx+5])
	}
	if msgType == "q" {
		searchStart := 0
		for {
			qi := strings.Index(s[searchStart:], "1:q")
			if qi < 0 {
				break
			}
			actualQi := searchStart + qi
			// If preceded by "1:y", this "1:q" is the value of "1:y1:q", not the key "1:q"
			if actualQi >= 3 && s[actualQi-3:actualQi] == "1:y" {
				searchStart = actualQi + 3
				continue
			}
			if actualQi+4 < len(s) {
				lenStart := actualQi + 3
				colonOffset := strings.Index(s[lenStart:], ":")
				if colonOffset > 0 && colonOffset <= 4 {
					lenEnd := lenStart + colonOffset
					var nameLen int
					if n, err := fmt.Sscanf(s[lenStart:lenEnd], "%d", &nameLen); n == 1 && err == nil {
						nameStart := lenEnd + 1
						if nameLen > 0 && nameLen <= 64 && nameStart+nameLen <= len(s) {
							methodName = s[nameStart : nameStart+nameLen]
						}
					}
				}
			}
			break
		}
	}
	return msgType, methodName
}

// ── uTP protocol (UDP, BEP 29) ───────────────────────────────────────────────

const utpHeaderSize = 20

func isUTPPacket(data []byte) bool {
	if len(data) < utpHeaderSize {
		return false
	}
	version := data[0] & 0x0F
	typ := (data[0] & 0xF0) >> 4
	return version == 1 && typ <= 4
}

func utpTypeName(data []byte) string {
	switch (data[0] & 0xF0) >> 4 {
	case 0:
		return "ST_DATA"
	case 1:
		return "ST_FIN"
	case 2:
		return "ST_STATE"
	case 3:
		return "ST_RESET"
	case 4:
		return "ST_SYN"
	default:
		return "UNKNOWN"
	}
}

// ── UDP Inspector ─────────────────────────────────────────────────────────────

type btUDPInspector struct {
	opts btOptions
}

func (i *btUDPInspector) InspectPacket(ctx sdk.Context, pkt *sdk.UDPPacket) (sdk.UDPVerdict, string, error) {
	if len(pkt.Payload) == 0 {
		return sdk.UDPVerdictDrop, "bt_udp_empty_packet", nil
	}

	// Global block mode.
	if i.opts.mode == modeBlock {
		if ctx != nil {
			ctx.OnSecurityEvent("blocked", "bt_blocked_by_policy")
		}
		return sdk.UDPVerdictDrop, "bt_blocked_by_policy", nil
	}

	if isDHTMessage(pkt.Payload) {
		return i.handleDHT(ctx, pkt)
	}
	if isUTPPacket(pkt.Payload) {
		return i.handleUTP(ctx, pkt)
	}
	return sdk.UDPVerdictAllow, "", nil
}

func (i *btUDPInspector) handleDHT(ctx sdk.Context, pkt *sdk.UDPPacket) (sdk.UDPVerdict, string, error) {
	// 1. Block all DHT.
	if i.opts.blockDHT {
		ctx.OnSecurityEvent("blocked", "bt_dht_blocked")
		return sdk.UDPVerdictDrop, "bt_dht_blocked", nil
	}

	// 2. Amplification protection: drop oversized packets.
	if i.opts.maxDHTPacketSize > 0 && len(pkt.Payload) > i.opts.maxDHTPacketSize {
		reason := fmt.Sprintf("bt_dht_packet_too_large: %d bytes (max %d)", len(pkt.Payload), i.opts.maxDHTPacketSize)
		ctx.OnSecurityEvent("blocked", reason)
		return sdk.UDPVerdictDrop, reason, nil
	}

	// 3. DHT method filtering — only applies to query packets.
	msgType, method := extractDHTMessageType(pkt.Payload)
	if msgType == "q" {
		if method == "" {
			if len(i.opts.allowedDHTMethods) > 0 {
				ctx.OnSecurityEvent("blocked", "bt_dht_query_missing_method")
				return sdk.UDPVerdictDrop, "bt_dht_query_missing_method", nil
			}
		} else {
			if ok, reason := i.opts.isDHTMethodAllowed(method); !ok {
				ctx.OnSecurityEvent("blocked", reason)
				return sdk.UDPVerdictDrop, reason, nil
			}
		}
	}

	reason := fmt.Sprintf("bt_dht_%s", msgType)
	if method != "" {
		reason = fmt.Sprintf("bt_dht_%s_%s", msgType, method)
	}
	ctx.OnSecurityEvent("inspect", reason)
	return sdk.UDPVerdictAllow, reason, nil
}

func (i *btUDPInspector) handleUTP(ctx sdk.Context, pkt *sdk.UDPPacket) (sdk.UDPVerdict, string, error) {
	if i.opts.blockUTP {
		ctx.OnSecurityEvent("blocked", "bt_utp_blocked")
		return sdk.UDPVerdictDrop, "bt_utp_blocked", nil
	}
	typName := utpTypeName(pkt.Payload)
	reason := fmt.Sprintf("bt_utp_%s", typName)
	ctx.OnSecurityEvent("inspect", reason)
	return sdk.UDPVerdictAllow, reason, nil
}

func (i *btUDPInspector) Close() error { return nil }
