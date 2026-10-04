package dns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

// ── domain matching tests ─────────────────────────────────────────────────────

func TestIsDomainBlocked_ExactMatch(t *testing.T) {
	blocked := []string{"malware.example.com", "ads.net"}
	cases := []struct {
		domain string
		want   bool
	}{
		{"malware.example.com", true},
		{"ads.net", true},
		{"safe.example.com", false},
		{"MALWARE.EXAMPLE.COM", true}, // case-insensitive
		{"", false},
	}
	for _, tc := range cases {
		got := isDomainBlocked(tc.domain, blocked)
		if got != tc.want {
			t.Errorf("isDomainBlocked(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestIsDomainBlocked_WildcardMatch(t *testing.T) {
	blocked := []string{"*.ads.example.com"}
	cases := []struct {
		domain string
		want   bool
	}{
		{"tracker.ads.example.com", true},
		{"deep.tracker.ads.example.com", true},
		// The base domain itself does NOT match — wildcards require at least one label prefix.
		{"ads.example.com", false},
		{"safe.example.com", false},
	}
	for _, tc := range cases {
		got := isDomainBlocked(tc.domain, blocked)
		if got != tc.want {
			t.Errorf("isDomainBlocked(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

// ── DNS query name extraction tests ──────────────────────────────────────────

func TestExtractDNSQueryName(t *testing.T) {
	// Build a minimal DNS query for "example.com" (A record, class IN).
	// Wire format: 12-byte header + QNAME labels + QTYPE + QCLASS.
	msg := buildDNSQuery("example.com")
	got := extractDNSQueryName(msg)
	if got != "example.com" {
		t.Errorf("extractDNSQueryName = %q, want %q", got, "example.com")
	}
}

func TestExtractDNSQueryName_TooShort(t *testing.T) {
	got := extractDNSQueryName([]byte{0x00, 0x01})
	if got != "" {
		t.Errorf("expected empty string for too-short message, got %q", got)
	}
}

func TestExtractDNSQueryName_NoQuestions(t *testing.T) {
	// QDCOUNT = 0
	msg := make([]byte, 12)
	got := extractDNSQueryName(msg)
	if got != "" {
		t.Errorf("expected empty string when QDCOUNT=0, got %q", got)
	}
}

// ── UDPInspector tests ────────────────────────────────────────────────────────

func TestDNSUDPInspector_AllowCleanQuery(t *testing.T) {
	p := &DNSPlugin{}
	insp, err := p.CreateUDPInspector(nil)
	if err != nil {
		t.Fatalf("CreateUDPInspector: %v", err)
	}
	defer insp.Close()

	pkt := &sdk.UDPPacket{
		Payload:    buildDNSQuery("safe.example.com"),
		ClientAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 53},
		IsReply:    false,
	}
	verdict, _, err := insp.InspectPacket(noopCtx(), pkt)
	if err != nil {
		t.Fatalf("InspectPacket: %v", err)
	}
	if verdict != sdk.UDPVerdictAllow {
		t.Errorf("expected Allow, got %v", verdict)
	}
}

func TestDNSUDPInspector_BlockListedDomain(t *testing.T) {
	p := &DNSPlugin{}
	insp, err := p.CreateUDPInspector(map[string]any{
		"blocked_domains": []any{"malware.example.com"},
	})
	if err != nil {
		t.Fatalf("CreateUDPInspector: %v", err)
	}
	defer insp.Close()

	pkt := &sdk.UDPPacket{
		Payload:    buildDNSQuery("malware.example.com"),
		ClientAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 53},
		IsReply:    false,
	}
	verdict, reason, err := insp.InspectPacket(noopCtx(), pkt)
	if err != nil {
		t.Fatalf("InspectPacket: %v", err)
	}
	if verdict != sdk.UDPVerdictDrop {
		t.Errorf("expected Drop for blocklisted domain, got %v", verdict)
	}
	if reason == "" {
		t.Error("expected non-empty reason for blocked domain")
	}
}

func TestDNSUDPInspector_DropOversizedPacket(t *testing.T) {
	p := &DNSPlugin{}
	insp, err := p.CreateUDPInspector(map[string]any{
		"max_packet_size": 10,
	})
	if err != nil {
		t.Fatalf("CreateUDPInspector: %v", err)
	}
	defer insp.Close()

	pkt := &sdk.UDPPacket{
		Payload:    make([]byte, 100), // exceeds max_packet_size: 10
		ClientAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 53},
		IsReply:    false,
	}
	verdict, _, err := insp.InspectPacket(noopCtx(), pkt)
	if err != nil {
		t.Fatalf("InspectPacket: %v", err)
	}
	if verdict != sdk.UDPVerdictDrop {
		t.Errorf("expected Drop for oversized packet, got %v", verdict)
	}
}

func TestDNSUDPInspector_AllowReplyDirection(t *testing.T) {
	p := &DNSPlugin{}
	insp, err := p.CreateUDPInspector(map[string]any{
		"blocked_domains": []any{"anything.com"},
	})
	if err != nil {
		t.Fatalf("CreateUDPInspector: %v", err)
	}
	defer insp.Close()

	// Even a query for a blocked domain should pass when IsReply=true.
	pkt := &sdk.UDPPacket{
		Payload:    buildDNSQuery("anything.com"),
		ClientAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 53},
		IsReply:    true,
	}
	verdict, _, _ := insp.InspectPacket(noopCtx(), pkt)
	if verdict != sdk.UDPVerdictAllow {
		t.Errorf("expected Allow for reply direction, got %v", verdict)
	}
}

// ── Plugin interface tests ────────────────────────────────────────────────────

func TestDNSPlugin_Manifest(t *testing.T) {
	p := &DNSPlugin{}
	m := p.Manifest()
	if m.Name != "dns" {
		t.Errorf("Manifest.Name = %q, want %q", m.Name, "dns")
	}
	if len(m.Protocols) == 0 {
		t.Error("Manifest.Protocols must not be empty")
	}
}

func TestDNSPlugin_ValidateConfig_Valid(t *testing.T) {
	p := &DNSPlugin{}
	err := p.ValidateConfig(map[string]any{
		"blocked_domains": []any{"evil.com"},
		"max_packet_size": 512,
	})
	if err != nil {
		t.Errorf("ValidateConfig: unexpected error: %v", err)
	}
}

func TestDNSPlugin_ValidateConfig_InvalidBlockedDomains(t *testing.T) {
	p := &DNSPlugin{}
	err := p.ValidateConfig(map[string]any{
		"blocked_domains": "not-a-list",
	})
	if err == nil {
		t.Error("expected error for non-list blocked_domains, got nil")
	}
}

func TestDNSPlugin_SelfTest(t *testing.T) {
	p := &DNSPlugin{}
	if err := p.SelfTest(); err != nil {
		t.Errorf("SelfTest failed: %v", err)
	}
}

func TestDNSPlugin_UDPManifest_MatchesManifest(t *testing.T) {
	p := &DNSPlugin{}
	if p.Manifest().Name != p.UDPManifest().Name {
		t.Error("UDPManifest() and Manifest() should return equivalent manifests")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// buildDNSQuery constructs a minimal DNS query message (wire format) for a given FQDN.
func buildDNSQuery(fqdn string) []byte {
	// Header: ID=0x1234, QR=0 (query), OPCODE=0, AA=0, TC=0, RD=1,
	//         RA=0, Z=0, RCODE=0, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	header := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: RD=1
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
	}

	var qname []byte
	labels := splitLabels(fqdn)
	for _, label := range labels {
		qname = append(qname, byte(len(label)))
		qname = append(qname, []byte(label)...)
	}
	qname = append(qname, 0x00) // root label

	// QTYPE=A (1), QCLASS=IN (1)
	qtype := []byte{0x00, 0x01, 0x00, 0x01}

	return append(append(header, qname...), qtype...)
}

func splitLabels(domain string) []string {
	var labels []string
	cur := ""
	for _, c := range domain {
		if c == '.' {
			if cur != "" {
				labels = append(labels, cur)
				cur = ""
			}
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		labels = append(labels, cur)
	}
	return labels
}

// noopCtx returns a minimal sdk.Context for tests.
func noopCtx() sdk.Context {
	return &sdk.DefaultContext{
		Ctx:         context.Background(),
		ServiceName: "dns-test",
	}
}

func TestIsDomainBlocked_TrailingDots(t *testing.T) {
	blocked := []string{"malware.example.com.", "*.ads.example.com."}
	if !isDomainBlocked("malware.example.com", blocked) {
		t.Error("expected malware.example.com to match blocked rule with trailing dot")
	}
	if !isDomainBlocked("malware.example.com.", blocked) {
		t.Error("expected malware.example.com. with trailing dot to match blocked rule")
	}
	if !isDomainBlocked("sub.ads.example.com.", blocked) {
		t.Error("expected sub.ads.example.com. with trailing dot to match wildcard rule")
	}
}

func TestExtractDNSQueryName_Malformed(t *testing.T) {
	// Label length > 63
	msg := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		64, // length > 63
	}
	if got := extractDNSQueryName(msg); got != "" {
		t.Errorf("extractDNSQueryName(length=64) = %q, want empty", got)
	}

	// Unterminated query (never hits length 0)
	msg2 := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 't', 'e', 's', 't',
	}
	if got := extractDNSQueryName(msg2); got != "" {
		t.Errorf("extractDNSQueryName(unterminated) = %q, want empty", got)
	}
}

func TestDNSTCPInspector_OversizedPacket(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	p := &DNSPlugin{}
	insp, err := p.CreateInspector(map[string]any{"max_packet_size": 512})
	if err != nil {
		t.Fatalf("CreateInspector: %v", err)
	}

	done := make(chan bool, 1)
	go func() {
		_, blocked, _, _ := insp.Run(noopCtx(), clientB, upA)
		done <- blocked
	}()

	// Send 2-byte length prefix of 1000 bytes (> 512 max)
	_, _ = clientA.Write([]byte{0x03, 0xE8})

	select {
	case blocked := <-done:
		if !blocked {
			t.Error("expected oversized TCP packet to be blocked")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for inspector")
	}
}

