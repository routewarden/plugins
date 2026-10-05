package smtp

import (
	"net"
	"strings"
	"testing"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func TestPluginManifest(t *testing.T) {
	p := &Plugin{}
	manifest := p.Manifest()

	if manifest.Name != "smtp" {
		t.Fatalf("expected plugin name 'smtp', got: %s", manifest.Name)
	}

	if len(manifest.Protocols) == 0 || manifest.Protocols[0] != "smtp" {
		t.Fatalf("expected protocol 'smtp', got: %v", manifest.Protocols)
	}
}

func TestPluginSelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest failed: %v", err)
	}
}

func TestSMTP_Run_BlockedSenderDomain(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	insp := &Inspector{
		BlockedSenderDomains: []string{"spam.org", "*.evil.com"},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, blocked, reason, _ := insp.Run(nil, clientConn, upConn)
		if !blocked {
			t.Errorf("expected blocked=true for spam.org sender domain")
		}
		if !strings.Contains(reason, "spam.org") {
			t.Errorf("expected reason to contain domain, got: %s", reason)
		}
	}()

	// Upstream sends 220 greeting
	go func() {
		_, _ = upPeer.Write([]byte("220 smtp.example.com ESMTP\r\n"))
	}()

	// Client reads greeting
	var buf [128]byte
	n, _ := clientPeer.Read(buf[:])
	if !strings.HasPrefix(string(buf[:n]), "220 ") {
		t.Fatalf("unexpected greeting: %s", string(buf[:n]))
	}

	// Client sends MAIL FROM with blocked domain
	go func() {
		_, _ = clientPeer.Write([]byte("MAIL FROM:<baduser@spam.org>\r\n"))
	}()

	// Client should receive 554 rejection
	n, _ = clientPeer.Read(buf[:])
	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "554 ") {
		t.Errorf("expected 554 rejection, got: %s", resp)
	}

	<-done
}

func TestSMTP_Run_AllowedSenderDomain(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	insp := &Inspector{
		BlockedSenderDomains: []string{"spam.org"},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, blocked, _, _ := insp.Run(nil, clientConn, upConn)
		if blocked {
			t.Errorf("expected allowed sender, got blocked")
		}
	}()

	// Upstream sends 220 greeting
	go func() {
		_, _ = upPeer.Write([]byte("220 smtp.example.com ESMTP\r\n"))
	}()

	// Client reads greeting
	var buf [128]byte
	_, _ = clientPeer.Read(buf[:])

	// Client sends MAIL FROM with legitimate domain
	go func() {
		_, _ = clientPeer.Write([]byte("MAIL FROM:<alice@company.com>\r\n"))
	}()

	// Upstream reads MAIL FROM and replies 250 OK
	upN, _ := upPeer.Read(buf[:])
	if !strings.Contains(string(buf[:upN]), "MAIL FROM") {
		t.Errorf("expected upstream to receive MAIL FROM, got: %s", string(buf[:upN]))
	}
	go func() {
		_, _ = upPeer.Write([]byte("250 2.1.0 OK\r\n"))
	}()

	// Client reads 250 OK
	n, _ := clientPeer.Read(buf[:])
	if !strings.HasPrefix(string(buf[:n]), "250 ") {
		t.Errorf("expected 250 OK, got: %s", string(buf[:n]))
	}

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}

func TestSMTP_Run_AuthFailure(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	authFailed := false
	ctx := &sdk.DefaultContext{
		ServiceName:   "smtp-test",
		ClientAddress: "127.0.0.1",
		AuthFailureFunc: func() {
			authFailed = true
		},
	}

	insp := &Inspector{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _, _ = insp.Run(ctx, clientConn, upConn)
	}()

	// Upstream sends greeting
	go func() {
		_, _ = upPeer.Write([]byte("220 smtp.example.com ESMTP\r\n"))
	}()

	var buf [128]byte
	_, _ = clientPeer.Read(buf[:])

	// Client sends AUTH LOGIN
	go func() {
		_, _ = clientPeer.Write([]byte("AUTH LOGIN\r\n"))
	}()

	// Upstream reads AUTH LOGIN and responds 535 auth failed
	upN, _ := upPeer.Read(buf[:])
	if !strings.Contains(string(buf[:upN]), "AUTH LOGIN") {
		t.Errorf("expected upstream to receive AUTH LOGIN, got: %s", string(buf[:upN]))
	}
	go func() {
		_, _ = upPeer.Write([]byte("535 5.7.8 Authentication credentials invalid\r\n"))
	}()

	// Client reads 535
	_, _ = clientPeer.Read(buf[:])

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done

	if !authFailed {
		t.Errorf("expected AuthFailureFunc to be called on 535 error response")
	}
}

func TestSMTP_ValidateConfig(t *testing.T) {
	p := &Plugin{}
	if err := p.ValidateConfig(nil); err != nil {
		t.Errorf("nil config rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"max_recipients": 10}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"max_recipients": "not-an-int"}); err == nil {
		t.Errorf("expected error for non-int max_recipients")
	}
}
