// Package dns provides a RouteWarden plugin for DNS protocol inspection.
//
// It implements both sdk.Plugin (DNS-over-TCP) and sdk.UDPPlugin (DNS-over-UDP),
// allowing a single plugin instance to guard DNS on both transports.
//
// # Capabilities
//   - Domain blocklist: drop queries for explicitly listed domains or wildcards (*.example.com)
//   - Packet size guard: drop malformed or oversized datagrams (amplification protection)
//   - Transparent passthrough for all other queries
//
// # Configuration
//
//	services:
//	  dns:
//	    listen: ":53"
//	    upstream: "1.1.1.1:53"
//	    transport: both    # bind UDP and TCP on :53
//	    protocol: dns
//	    udp:
//	      session_timeout: 30s
//	      max_sessions: 10000
//	    plugin_config:
//	      blocked_domains:
//	        - "malware.example.com"
//	        - "*.ads.example.net"
//	      max_packet_size: 4096
package dns

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

//go:embed plugin.yaml
var manifestYAML []byte

func init() {
	plugins.Register(&DNSPlugin{})
}

// DNSPlugin implements sdk.Plugin (TCP) and sdk.UDPPlugin (UDP).
type DNSPlugin struct{}

// Plugin is an alias for DNSPlugin for standard modular plugin naming.
type Plugin = DNSPlugin

// ── sdk.Plugin (DNS-over-TCP) ────────────────────────────────────────────────

func (p *DNSPlugin) Manifest() sdk.Manifest {
	return sdk.MustParseManifest(manifestYAML)
}

func (p *DNSPlugin) ValidateConfig(config map[string]any) error {
	return parseOptions(config) // reuse the same options parser
}

func (p *DNSPlugin) SelfTest() error {
	// Verify the TCP inspector can be created with an empty config.
	_, err := p.CreateInspector(nil)
	return err
}

func (p *DNSPlugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	opts, err := parseOpts(config)
	if err != nil {
		return nil, err
	}
	return &dnsTCPInspector{opts: opts}, nil
}

// ── sdk.UDPPlugin (DNS-over-UDP) ─────────────────────────────────────────────

func (p *DNSPlugin) UDPManifest() sdk.Manifest {
	return sdk.MustParseManifest(manifestYAML)
}

func (p *DNSPlugin) CreateUDPInspector(config map[string]any) (sdk.UDPInspector, error) {
	opts, err := parseOpts(config)
	if err != nil {
		return nil, err
	}
	return &dnsUDPInspector{opts: opts}, nil
}

// ── Options ───────────────────────────────────────────────────────────────────

type dnsOptions struct {
	blockedDomains []string // plain or wildcard (*.example.com)
	maxPacketSize  int      // 0 = use defaultMaxDNSPacket
}

const defaultMaxDNSPacket = 4096

func parseOptions(config map[string]any) error {
	_, err := parseOpts(config)
	return err
}

func parseOpts(config map[string]any) (dnsOptions, error) {
	opts := dnsOptions{maxPacketSize: defaultMaxDNSPacket}
	if config == nil {
		return opts, nil
	}
	if v, ok := config["blocked_domains"]; ok {
		switch val := v.(type) {
		case []string:
			opts.blockedDomains = val
		case []any:
			for _, item := range val {
				if s, ok := item.(string); ok {
					opts.blockedDomains = append(opts.blockedDomains, strings.ToLower(s))
				}
			}
		default:
			return opts, fmt.Errorf("dns: blocked_domains must be a list of strings")
		}
	}
	if v, ok := config["max_packet_size"]; ok {
		switch val := v.(type) {
		case int:
			opts.maxPacketSize = val
		case float64:
			opts.maxPacketSize = int(val)
		}
	}
	return opts, nil
}

// isDomainBlocked checks whether qname matches any entry in the blocklist.
// isDomainBlocked checks whether qname matches any entry in the blocklist.
// Supports exact matches and wildcard prefixes (*.example.com).
// A wildcard *.foo.com matches sub.foo.com and a.b.foo.com but NOT foo.com itself.
func isDomainBlocked(qname string, blocked []string) bool {
	qname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
	for _, pattern := range blocked {
		pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
		if strings.HasPrefix(pattern, "*.") {
			// *.foo.com → suffix = ".foo.com"
			// qname must end with ".foo.com" (i.e. be a proper subdomain).
			suffix := pattern[1:] // e.g. ".ads.example.com"
			if strings.HasSuffix(qname, suffix) {
				return true
			}
		} else {
			if qname == pattern {
				return true
			}
		}
	}
	return false
}

// extractDNSQueryName parses the first QNAME from a raw DNS message (wire format).
// Returns "" if the message is malformed.
func extractDNSQueryName(msg []byte) string {
	names := extractDNSQueryNames(msg)
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

// extractDNSQueryNames parses all QNAMEs for all questions in a DNS message using dnsmessage.Parser.
func extractDNSQueryNames(msg []byte) []string {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil
	}
	var names []string
	for {
		q, err := p.Question()
		if err != nil {
			break
		}
		name := strings.TrimSuffix(q.Name.String(), ".")
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

// ── DNS-over-UDP Inspector ────────────────────────────────────────────────────

type dnsUDPInspector struct {
	opts dnsOptions
}

func (i *dnsUDPInspector) InspectPacket(ctx sdk.Context, pkt *sdk.UDPPacket) (sdk.UDPVerdict, string, error) {
	// Only inspect client → upstream direction.
	if pkt.IsReply {
		return sdk.UDPVerdictAllow, "", nil
	}

	// 1. Packet size guard (amplification protection).
	if i.opts.maxPacketSize > 0 && len(pkt.Payload) > i.opts.maxPacketSize {
		if ctx != nil {
			ctx.OnSecurityEvent("blocked", fmt.Sprintf("dns_packet_too_large: %d bytes", len(pkt.Payload)))
		}
		return sdk.UDPVerdictDrop, fmt.Sprintf("dns_packet_too_large: %d bytes", len(pkt.Payload)), nil
	}

	// 2. Domain blocklist.
	if len(i.opts.blockedDomains) > 0 {
		qnames := extractDNSQueryNames(pkt.Payload)
		for _, qname := range qnames {
			if isDomainBlocked(qname, i.opts.blockedDomains) {
				if ctx != nil {
					ctx.OnSecurityEvent("blocked", fmt.Sprintf("dns_blocked_domain: %s", qname))
				}
				return sdk.UDPVerdictDrop, fmt.Sprintf("dns_blocked_domain: %s", qname), nil
			}
		}
	}

	return sdk.UDPVerdictAllow, "", nil
}

func (i *dnsUDPInspector) Close() error { return nil }

// ── DNS-over-TCP Inspector ────────────────────────────────────────────────────

// dnsTCPInspector forwards DNS-over-TCP with domain blocklist enforcement.
// DNS-over-TCP prefixes each message with a 2-byte length field.
type dnsTCPInspector struct {
	opts dnsOptions
}

func (i *dnsTCPInspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	// For TCP, we read the 2-byte length prefix + message, check the domain,
	// then proxy the rest of the stream transparently if allowed.
	var result sdk.ProxyResult

	client.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read the 2-byte length prefix.
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, lenBuf); err != nil {
		return result, false, "", err
	}
	msgLen := int(binary.BigEndian.Uint16(lenBuf))
	if msgLen == 0 {
		return result, false, "", errors.New("dns-tcp: zero-length message")
	}

	if i.opts.maxPacketSize > 0 && msgLen > i.opts.maxPacketSize {
		if ctx != nil {
			ctx.OnSecurityEvent("blocked", fmt.Sprintf("dns_packet_too_large: %d bytes", msgLen))
		}
		return result, true, fmt.Sprintf("dns_packet_too_large: %d bytes", msgLen), nil
	}

	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(client, msgBuf); err != nil {
		return result, false, "", err
	}

	// Check domain blocklist.
	if len(i.opts.blockedDomains) > 0 {
		qnames := extractDNSQueryNames(msgBuf)
		for _, qname := range qnames {
			if isDomainBlocked(qname, i.opts.blockedDomains) {
				if ctx != nil {
					ctx.OnSecurityEvent("blocked", fmt.Sprintf("dns_blocked_domain: %s", qname))
				}
				return result, true, fmt.Sprintf("dns_blocked_domain: %s", qname), nil
			}
		}
	}

	// Forward the initial message (length prefix + body) to upstream.
	full := append(lenBuf, msgBuf...)
	n, err := upstream.Write(full)
	result.BytesIn = int64(n)
	if err != nil {
		return result, false, "", err
	}

	client.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})

	// Proxy remainder of the session transparently.
	res := protocol.Proxy(client, upstream)
	result.BytesIn += res.BytesIn
	result.BytesOut = res.BytesOut
	return result, false, "", res.Err
}
