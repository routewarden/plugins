package bittorrent

import (
	"context"
	"encoding/hex"
	"net"
	"strings"
	"testing"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

// ── Handshake parsing ─────────────────────────────────────────────────────────

func TestParseHandshake_Valid(t *testing.T) {
	hexHash := "aabbccddeeff00112233445566778899aabbccdd"
	raw := syntheticHandshake(hexHash, "-RW0100-123456789012")
	hs, err := parseHandshake(raw)
	if err != nil {
		t.Fatalf("parseHandshake: %v", err)
	}
	if hs.InfoHash != hexHash {
		t.Errorf("InfoHash = %q, want %q", hs.InfoHash, hexHash)
	}
}

func TestParseHandshake_TooShort(t *testing.T) {
	_, err := parseHandshake(make([]byte, 10))
	if err == nil {
		t.Error("expected error for too-short handshake")
	}
}

func TestParseHandshake_NotBT(t *testing.T) {
	buf := make([]byte, 68)
	buf[0] = 0x05
	_, err := parseHandshake(buf)
	if err == nil {
		t.Error("expected error for non-BT handshake")
	}
}

func TestIsBitTorrentHandshake(t *testing.T) {
	raw := syntheticHandshake("aabbccddeeff00112233445566778899aabbccdd", "-RW0100-123456789012")
	if !isBitTorrentHandshake(raw) {
		t.Error("expected true for valid BT handshake")
	}
	if isBitTorrentHandshake(make([]byte, 68)) {
		t.Error("expected false for zero buffer")
	}
}

func TestDescribeExtensions_Multiple(t *testing.T) {
	var flags [8]byte
	flags[7] |= extFlagDHT
	flags[5] |= extFlagExtProto
	desc := describeExtensions(flags)
	if !strings.Contains(desc, "DHT") || !strings.Contains(desc, "ExtProto") {
		t.Errorf("describeExtensions = %q, expected DHT and ExtProto", desc)
	}
}

func TestDescribeExtensions_None(t *testing.T) {
	if describeExtensions([8]byte{}) != "none" {
		t.Error("expected 'none' for zero flags")
	}
}

// ── Info hash policy ──────────────────────────────────────────────────────────

func TestIsInfoHashAllowed_Blocklist(t *testing.T) {
	badHash := "aabbccddeeff00112233445566778899aabbccdd"
	opts := btOptions{
		blockedInfoHashes: map[string]struct{}{badHash: {}},
		allowedInfoHashes: map[string]struct{}{},
		blockedDHTMethods: map[string]struct{}{},
		allowedDHTMethods: map[string]struct{}{},
	}
	ok, reason := opts.isInfoHashAllowed(badHash)
	if ok {
		t.Error("expected blocklisted hash to be denied")
	}
	if !strings.Contains(reason, "bt_blocked_info_hash") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestIsInfoHashAllowed_Allowlist(t *testing.T) {
	goodHash := "1122334455667788990011223344556677889900"
	badHash := "aabbccddeeff00112233445566778899aabbccdd"
	opts := btOptions{
		blockedInfoHashes: map[string]struct{}{},
		allowedInfoHashes: map[string]struct{}{goodHash: {}},
		blockedDHTMethods: map[string]struct{}{},
		allowedDHTMethods: map[string]struct{}{},
	}
	if ok, _ := opts.isInfoHashAllowed(goodHash); !ok {
		t.Error("allowlisted hash should be allowed")
	}
	if ok, _ := opts.isInfoHashAllowed(badHash); ok {
		t.Error("non-allowlisted hash should be denied")
	}
}

func TestIsInfoHashAllowed_CaseInsensitive(t *testing.T) {
	lower := "aabbccddeeff00112233445566778899aabbccdd"
	opts := btOptions{
		blockedInfoHashes: map[string]struct{}{lower: {}},
		allowedInfoHashes: map[string]struct{}{},
		blockedDHTMethods: map[string]struct{}{},
		allowedDHTMethods: map[string]struct{}{},
	}
	if ok, _ := opts.isInfoHashAllowed(strings.ToUpper(lower)); ok {
		t.Error("uppercase hash should match blocklist case-insensitively")
	}
}

// ── Peer ID controls ──────────────────────────────────────────────────────────

func TestIsPeerIDAllowed_ValidFormat(t *testing.T) {
	opts := btOptions{requirePeerIDFormat: true, blockedDHTMethods: map[string]struct{}{}, allowedDHTMethods: map[string]struct{}{}}
	ok, _ := opts.isPeerIDAllowed("-qB4600-XXXXXXXXXXXX")
	if !ok {
		t.Error("valid Azureus-style peer ID should be allowed")
	}
}

func TestIsPeerIDAllowed_InvalidFormat(t *testing.T) {
	opts := btOptions{requirePeerIDFormat: true, blockedDHTMethods: map[string]struct{}{}, allowedDHTMethods: map[string]struct{}{}}
	// Scanner-style peer ID without the format
	ok, reason := opts.isPeerIDAllowed("masscan/1.0.0")
	if ok {
		t.Error("non-Azureus peer ID should be blocked with require_peer_id_format=true")
	}
	if !strings.Contains(reason, "bt_invalid_peer_id_format") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestIsPeerIDAllowed_BlockedPrefix(t *testing.T) {
	opts := btOptions{
		blockedPeerIDPrefixes: []string{"-BS-"},
		blockedDHTMethods:     map[string]struct{}{},
		allowedDHTMethods:     map[string]struct{}{},
	}
	ok, reason := opts.isPeerIDAllowed("-BS0100-XXXXXXXXXXXX")
	if ok {
		t.Error("blocked prefix peer ID should be denied")
	}
	if !strings.Contains(reason, "bt_blocked_peer_id_prefix") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestIsPeerIDAllowed_AllowedPrefixList(t *testing.T) {
	opts := btOptions{
		allowedPeerIDPrefixes: []string{"-qB-", "-TR-"},
		blockedDHTMethods:     map[string]struct{}{},
		allowedDHTMethods:     map[string]struct{}{},
	}
	if ok, _ := opts.isPeerIDAllowed("-qB4600-XXXXXXXXXXXX"); !ok {
		t.Error("qBittorrent should be allowed")
	}
	if ok, _ := opts.isPeerIDAllowed("-TR3000-XXXXXXXXXXXX"); !ok {
		t.Error("Transmission should be allowed")
	}
	if ok, _ := opts.isPeerIDAllowed("-UM3200-XXXXXXXXXXXX"); ok {
		t.Error("unlisted client should be denied by allowlist")
	}
}

// ── Extension flag policy ─────────────────────────────────────────────────────

func TestAreExtensionsAllowed_PrivateTrackerMode(t *testing.T) {
	opts := btOptions{privateTrackerMode: true, blockedDHTMethods: map[string]struct{}{}, allowedDHTMethods: map[string]struct{}{}}
	var flags [8]byte
	flags[7] |= extFlagDHT
	ok, reason := opts.areExtensionsAllowed(flags)
	if ok {
		t.Error("private tracker mode should reject peers advertising DHT")
	}
	if !strings.Contains(reason, "bt_private_tracker_dht_rejected") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestAreExtensionsAllowed_PrivateTrackerMode_NoDHT(t *testing.T) {
	opts := btOptions{privateTrackerMode: true, blockedDHTMethods: map[string]struct{}{}, allowedDHTMethods: map[string]struct{}{}}
	var flags [8]byte // no DHT bit
	ok, _ := opts.areExtensionsAllowed(flags)
	if !ok {
		t.Error("peer without DHT bit should be allowed in private tracker mode")
	}
}

func TestAreExtensionsAllowed_BlockedExtension(t *testing.T) {
	opts := btOptions{
		blockedExtensions: [][2]byte{{5, extFlagExtProto}},
		blockedDHTMethods: map[string]struct{}{},
		allowedDHTMethods: map[string]struct{}{},
	}
	var flags [8]byte
	flags[5] |= extFlagExtProto
	ok, reason := opts.areExtensionsAllowed(flags)
	if ok {
		t.Error("blocked extension bit should deny peer")
	}
	if !strings.Contains(reason, "bt_blocked_extension") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestAreExtensionsAllowed_RequiredExtension_Missing(t *testing.T) {
	opts := btOptions{
		requiredExtensions: [][2]byte{{7, extFlagFast}},
		blockedDHTMethods:  map[string]struct{}{},
		allowedDHTMethods:  map[string]struct{}{},
	}
	var flags [8]byte // Fast extension NOT set
	ok, reason := opts.areExtensionsAllowed(flags)
	if ok {
		t.Error("peer missing required extension should be denied")
	}
	if !strings.Contains(reason, "bt_missing_required_extension") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestAreExtensionsAllowed_RequiredExtension_Present(t *testing.T) {
	opts := btOptions{
		requiredExtensions: [][2]byte{{7, extFlagFast}},
		blockedDHTMethods:  map[string]struct{}{},
		allowedDHTMethods:  map[string]struct{}{},
	}
	var flags [8]byte
	flags[7] |= extFlagFast
	ok, _ := opts.areExtensionsAllowed(flags)
	if !ok {
		t.Error("peer with required extension present should be allowed")
	}
}

// ── DHT method filtering ──────────────────────────────────────────────────────

func TestIsDHTMethodAllowed_BlockedMethod(t *testing.T) {
	opts := btOptions{
		blockedDHTMethods: map[string]struct{}{"announce_peer": {}},
		allowedDHTMethods: map[string]struct{}{},
	}
	ok, reason := opts.isDHTMethodAllowed("announce_peer")
	if ok {
		t.Error("blocked DHT method should be denied")
	}
	if !strings.Contains(reason, "bt_dht_method_blocked") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestIsDHTMethodAllowed_AllowlistMode(t *testing.T) {
	opts := btOptions{
		blockedDHTMethods: map[string]struct{}{},
		allowedDHTMethods: map[string]struct{}{"ping": {}, "find_node": {}},
	}
	if ok, _ := opts.isDHTMethodAllowed("ping"); !ok {
		t.Error("allowlisted method should pass")
	}
	if ok, _ := opts.isDHTMethodAllowed("get_peers"); ok {
		t.Error("non-allowlisted method should be denied")
	}
}

// ── DHT amplification protection ─────────────────────────────────────────────

func TestBTUDPInspector_DHTAmplificationProtection(t *testing.T) {
	p := &BitTorrentPlugin{}
	insp, err := p.CreateUDPInspector(map[string]any{
		"max_dht_packet_size": 100,
	})
	if err != nil {
		t.Fatalf("CreateUDPInspector: %v", err)
	}
	defer insp.Close()

	pkt := &sdk.UDPPacket{
		Payload:    append([]byte("d"), make([]byte, 200)...),
		ClientAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 6881},
	}
	// make it look like bencode dict
	pkt.Payload[0] = 'd'
	pkt.Payload[len(pkt.Payload)-1] = 'e'

	verdict, reason, _ := insp.InspectPacket(btUDPCtx(), pkt)
	if verdict != sdk.UDPVerdictDrop {
		t.Errorf("expected Drop for oversized DHT packet, got %v", verdict)
	}
	if !strings.Contains(reason, "bt_dht_packet_too_large") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestBTUDPInspector_DHTMethodBlocked(t *testing.T) {
	p := &BitTorrentPlugin{}
	insp, err := p.CreateUDPInspector(map[string]any{
		"blocked_dht_methods": []any{"announce_peer"},
	})
	if err != nil {
		t.Fatalf("CreateUDPInspector: %v", err)
	}
	defer insp.Close()

	// announce_peer query
	pkt := &sdk.UDPPacket{
		Payload:    []byte("d1:q13:announce_peer1:t2:aa1:y1:qe"),
		ClientAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 6881},
	}
	verdict, reason, _ := insp.InspectPacket(btUDPCtx(), pkt)
	if verdict != sdk.UDPVerdictDrop {
		t.Errorf("expected Drop for blocked DHT method, got %v", verdict)
	}
	if !strings.Contains(reason, "announce_peer") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

// ── TCP Inspector full pipeline tests ────────────────────────────────────────

func TestBTTCPInspector_BlockAll(t *testing.T) {
	p := &BitTorrentPlugin{}
	insp, err := p.CreateInspector(map[string]any{"mode": "block"})
	if err != nil {
		t.Fatalf("CreateInspector: %v", err)
	}
	client, serverSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	go func() {
		serverSide.Write(syntheticHandshake("aabbccddeeff00112233445566778899aabbccdd", "-RW0100-XXXXXXXXXXXX"))
		serverSide.Close()
	}()
	defer client.Close()
	defer upstreamSide.Close()
	_, blocked, reason, _ := insp.Run(btTestCtx(), client, upstream)
	if !blocked {
		t.Errorf("expected blocked=true, got blocked=%v reason=%q", blocked, reason)
	}
	if !strings.Contains(reason, "bt_blocked_by_policy") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestBTTCPInspector_BlockedInfoHash(t *testing.T) {
	badHash := "aabbccddeeff00112233445566778899aabbccdd"
	p := &BitTorrentPlugin{}
	insp, err := p.CreateInspector(map[string]any{
		"blocked_info_hashes": []any{badHash},
	})
	if err != nil {
		t.Fatalf("CreateInspector: %v", err)
	}
	client, serverSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	go func() {
		serverSide.Write(syntheticHandshake(badHash, "-RW0100-XXXXXXXXXXXX"))
		serverSide.Close()
	}()
	defer client.Close()
	defer upstreamSide.Close()
	_, blocked, reason, _ := insp.Run(btTestCtx(), client, upstream)
	if !blocked {
		t.Errorf("expected blocked=true for blocklisted info hash")
	}
	if !strings.Contains(reason, "bt_blocked_info_hash") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestBTTCPInspector_BlockedPeerIDPrefix(t *testing.T) {
	p := &BitTorrentPlugin{}
	insp, err := p.CreateInspector(map[string]any{
		"blocked_peer_id_prefixes": []any{"-BS-"},
	})
	if err != nil {
		t.Fatalf("CreateInspector: %v", err)
	}
	client, serverSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	go func() {
		serverSide.Write(syntheticHandshake("aabbccddeeff00112233445566778899aabbccdd", "-BS0200-XXXXXXXXXXXX"))
		serverSide.Close()
	}()
	defer client.Close()
	defer upstreamSide.Close()
	_, blocked, reason, _ := insp.Run(btTestCtx(), client, upstream)
	if !blocked {
		t.Errorf("expected blocked=true for blocked peer ID prefix")
	}
	if !strings.Contains(reason, "bt_blocked_peer_id_prefix") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestBTTCPInspector_PrivateTrackerMode(t *testing.T) {
	p := &BitTorrentPlugin{}
	insp, err := p.CreateInspector(map[string]any{
		"private_tracker_mode": true,
	})
	if err != nil {
		t.Fatalf("CreateInspector: %v", err)
	}
	client, serverSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	go func() {
		// Peer with DHT bit set in extension flags
		var flags [8]byte
		flags[7] |= extFlagDHT
		serverSide.Write(syntheticHandshakeWithFlags("aabbccddeeff00112233445566778899aabbccdd", "-qB4600-XXXXXXXXXXXX", flags))
		serverSide.Close()
	}()
	defer client.Close()
	defer upstreamSide.Close()
	_, blocked, reason, _ := insp.Run(btTestCtx(), client, upstream)
	if !blocked {
		t.Errorf("expected blocked=true for DHT peer in private tracker mode")
	}
	if !strings.Contains(reason, "bt_private_tracker_dht_rejected") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestBTTCPInspector_NonBTPassthrough(t *testing.T) {
	p := &BitTorrentPlugin{}
	insp, err := p.CreateInspector(map[string]any{"mode": "block"})
	if err != nil {
		t.Fatalf("CreateInspector: %v", err)
	}
	client, serverSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	go func() {
		payload := make([]byte, 68)
		copy(payload, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n"))
		serverSide.Write(payload)
		serverSide.Close()
	}()
	go func() {
		buf := make([]byte, 128)
		upstreamSide.Read(buf)
		upstreamSide.Close()
	}()
	defer client.Close()
	_, blocked, _, _ := insp.Run(btTestCtx(), client, upstream)
	if blocked {
		t.Error("non-BT traffic must pass through even in block mode")
	}
}

// ── UDP Inspector basic tests ─────────────────────────────────────────────────

func TestBTUDPInspector_BlockDHT(t *testing.T) {
	p := &BitTorrentPlugin{}
	insp, err := p.CreateUDPInspector(map[string]any{"block_dht": true})
	if err != nil {
		t.Fatalf("CreateUDPInspector: %v", err)
	}
	defer insp.Close()
	pkt := &sdk.UDPPacket{Payload: []byte("d1:t2:aa1:y1:qe"), ClientAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 6881}}
	verdict, reason, _ := insp.InspectPacket(btUDPCtx(), pkt)
	if verdict != sdk.UDPVerdictDrop {
		t.Errorf("expected Drop, got %v", verdict)
	}
	if !strings.Contains(reason, "bt_dht_blocked") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestBTUDPInspector_AllowDHT(t *testing.T) {
	p := &BitTorrentPlugin{}
	insp, err := p.CreateUDPInspector(map[string]any{"block_dht": false})
	if err != nil {
		t.Fatalf("CreateUDPInspector: %v", err)
	}
	defer insp.Close()
	pkt := &sdk.UDPPacket{Payload: []byte("d1:t2:aa1:y1:qe"), ClientAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 6881}}
	verdict, _, _ := insp.InspectPacket(btUDPCtx(), pkt)
	if verdict != sdk.UDPVerdictAllow {
		t.Errorf("expected Allow, got %v", verdict)
	}
}

func TestBTUDPInspector_BlockUTP(t *testing.T) {
	p := &BitTorrentPlugin{}
	insp, err := p.CreateUDPInspector(map[string]any{"block_utp": true})
	if err != nil {
		t.Fatalf("CreateUDPInspector: %v", err)
	}
	defer insp.Close()
	pkt := &sdk.UDPPacket{Payload: syntheticUTPPacket(4), ClientAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 6881}}
	verdict, reason, _ := insp.InspectPacket(btUDPCtx(), pkt)
	if verdict != sdk.UDPVerdictDrop {
		t.Errorf("expected Drop, got %v", verdict)
	}
	if !strings.Contains(reason, "bt_utp_blocked") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestBTUDPInspector_GlobalBlockMode(t *testing.T) {
	p := &BitTorrentPlugin{}
	insp, err := p.CreateUDPInspector(map[string]any{"mode": "block"})
	if err != nil {
		t.Fatalf("CreateUDPInspector: %v", err)
	}
	defer insp.Close()
	pkt := &sdk.UDPPacket{Payload: []byte("d1:y1:qe"), ClientAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 6881}}
	verdict, reason, _ := insp.InspectPacket(btUDPCtx(), pkt)
	if verdict != sdk.UDPVerdictDrop {
		t.Errorf("expected Drop in global block mode, got %v", verdict)
	}
	if !strings.Contains(reason, "bt_blocked_by_policy") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

// ── parseOpts validation ──────────────────────────────────────────────────────

func TestParseOpts_InvalidMode(t *testing.T) {
	_, err := parseOpts(map[string]any{"mode": "stealth"})
	if err == nil {
		t.Error("expected error for unknown mode")
	}
}

func TestParseOpts_InvalidHashHex(t *testing.T) {
	_, err := parseOpts(map[string]any{"blocked_info_hashes": []any{"not-valid-hex"}})
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestParseOpts_HashWrongLength(t *testing.T) {
	_, err := parseOpts(map[string]any{"blocked_info_hashes": []any{"aabb"}})
	if err == nil {
		t.Error("expected error for info hash that is not 20 bytes")
	}
}

func TestParseOpts_UnknownExtension(t *testing.T) {
	_, err := parseOpts(map[string]any{"blocked_extensions": []any{"nonexistent"}})
	if err == nil {
		t.Error("expected error for unknown extension name")
	}
}

func TestParseOpts_ValidExtensionNames(t *testing.T) {
	_, err := parseOpts(map[string]any{
		"blocked_extensions":  []any{"dht"},
		"required_extensions": []any{"extproto"},
	})
	if err != nil {
		t.Errorf("unexpected error for valid extension names: %v", err)
	}
}

// ── DHT detection ─────────────────────────────────────────────────────────────

func TestIsDHTMessage(t *testing.T) {
	cases := []struct {
		data []byte
		want bool
	}{
		{[]byte("d1:t2:aa1:y1:qe"), true},
		{[]byte("d1:y1:re"), true},
		{[]byte{0x41, 0x01, 0x00, 0x00}, false},
		{[]byte("not-bencode"), false},
		{nil, false},
	}
	for _, tc := range cases {
		if got := isDHTMessage(tc.data); got != tc.want {
			t.Errorf("isDHTMessage(%q) = %v, want %v", tc.data, got, tc.want)
		}
	}
}

func TestExtractDHTMessageType_Query(t *testing.T) {
	msg := []byte("d1:q4:ping1:t2:aa1:y1:qe")
	msgType, method := extractDHTMessageType(msg)
	if msgType != "q" {
		t.Errorf("msgType = %q, want %q", msgType, "q")
	}
	if method != "ping" {
		t.Errorf("method = %q, want %q", method, "ping")
	}
}

func TestExtractDHTMessageType_Response(t *testing.T) {
	msg := []byte("d1:rd2:id20:aaaaaaaaaaaaaaaaaaaaee1:t2:aa1:y1:re")
	msgType, _ := extractDHTMessageType(msg)
	if msgType != "r" {
		t.Errorf("msgType = %q, want %q", msgType, "r")
	}
}

// ── uTP detection ─────────────────────────────────────────────────────────────

func TestIsUTPPacket(t *testing.T) {
	for _, typ := range []byte{0, 1, 2, 3, 4} {
		if !isUTPPacket(syntheticUTPPacket(typ)) {
			t.Errorf("isUTPPacket(type=%d) = false, want true", typ)
		}
	}
	bad := make([]byte, utpHeaderSize)
	bad[0] = 0x42 // version = 2
	if isUTPPacket(bad) {
		t.Error("expected false for version != 1")
	}
}

func TestUTPTypeName(t *testing.T) {
	cases := map[byte]string{0: "ST_DATA", 1: "ST_FIN", 2: "ST_STATE", 3: "ST_RESET", 4: "ST_SYN"}
	for typ, want := range cases {
		if got := utpTypeName(syntheticUTPPacket(typ)); got != want {
			t.Errorf("utpTypeName(type=%d) = %q, want %q", typ, got, want)
		}
	}
}

// ── Plugin interface surface ──────────────────────────────────────────────────

func TestBitTorrentPlugin_Manifest(t *testing.T) {
	p := &BitTorrentPlugin{}
	m := p.Manifest()
	if m.Name != "bittorrent" {
		t.Errorf("Name = %q, want %q", m.Name, "bittorrent")
	}
	if len(m.Protocols) == 0 {
		t.Error("Protocols must not be empty")
	}
}

func TestBitTorrentPlugin_SelfTest(t *testing.T) {
	if err := (&BitTorrentPlugin{}).SelfTest(); err != nil {
		t.Errorf("SelfTest: %v", err)
	}
}

func TestBitTorrentPlugin_UDPManifestMatchesManifest(t *testing.T) {
	p := &BitTorrentPlugin{}
	if p.Manifest().Name != p.UDPManifest().Name {
		t.Error("UDPManifest() and Manifest() should match")
	}
}

func TestExtractDHTMessageType_MalformedNegativeLength(t *testing.T) {
	// Malformed DHT packet with negative name length or overflow should not panic
	malformed := []byte("d1:y1:q1:q-5:foobare")
	msgType, method := extractDHTMessageType(malformed)
	if msgType != "q" {
		t.Errorf("msgType = %q, want q", msgType)
	}
	if method != "" {
		t.Errorf("method = %q, want empty", method)
	}

	malformed2 := []byte("d1:y1:q1:q99999999:fooe")
	_, method2 := extractDHTMessageType(malformed2)
	if method2 != "" {
		t.Errorf("method2 = %q, want empty", method2)
	}
}

func TestBTUDPInspector_GlobalBlockSecurityEvent(t *testing.T) {
	var eventFired bool
	ctx := &sdk.DefaultContext{
		Ctx:         context.Background(),
		ServiceName: "bt-test",
		SecurityFunc: func(action, reason string) {
			if action == "blocked" && reason == "bt_blocked_by_policy" {
				eventFired = true
			}
		},
	}
	p := &BitTorrentPlugin{}
	insp, err := p.CreateUDPInspector(map[string]any{"mode": "block"})
	if err != nil {
		t.Fatalf("CreateUDPInspector: %v", err)
	}
	pkt := &sdk.UDPPacket{
		Payload:    []byte("some-data"),
		ClientAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1234},
	}
	verdict, reason, err := insp.InspectPacket(ctx, pkt)
	if err != nil {
		t.Fatalf("InspectPacket: %v", err)
	}
	if verdict != sdk.UDPVerdictDrop {
		t.Errorf("verdict = %v, want Drop", verdict)
	}
	if reason != "bt_blocked_by_policy" {
		t.Errorf("reason = %q, want bt_blocked_by_policy", reason)
	}
	if !eventFired {
		t.Error("expected security event 'blocked' to be fired")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func syntheticUTPPacket(typ byte) []byte {
	buf := make([]byte, utpHeaderSize)
	buf[0] = (typ << 4) | 0x01
	return buf
}

func btTestCtx() sdk.Context {
	return &sdk.DefaultContext{
		Ctx:          context.Background(),
		ServiceName:  "bittorrent-test",
		SecurityFunc: func(_, _ string) {},
	}
}

func btUDPCtx() sdk.Context {
	return &sdk.DefaultContext{
		Ctx:          context.Background(),
		ServiceName:  "bittorrent-udp-test",
		SecurityFunc: func(_, _ string) {},
	}
}

// hexHash20 builds a valid 20-byte info hash from a short prefix for tests.
func hexHash20(prefix string) string {
	b := make([]byte, 20)
	copy(b, []byte(prefix))
	return hex.EncodeToString(b)
}
