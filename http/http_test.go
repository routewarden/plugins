package http

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func TestHTTP_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest() failed: %v", err)
	}
}

func TestHTTP_ValidateConfig(t *testing.T) {
	p := &Plugin{}

	valid := map[string]any{
		"allowed_hosts":       []any{"example.com", "*.internal.net"},
		"blocked_user_agents": []any{"sqlmap", "nikto"},
		"allowed_paths":       []any{"/api/*", "/health"},
	}
	if err := p.ValidateConfig(valid); err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}

	invalid := map[string]any{
		"allowed_hosts": 12345,
	}
	if err := p.ValidateConfig(invalid); err == nil {
		t.Fatal("expected error for invalid allowed_hosts type, got nil")
	}
}

func TestHTTP_BlockedHost(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	var securityAction, securityReason string
	ctx := &sdk.DefaultContext{
		SecurityFunc: func(action, reason string) {
			securityAction = action
			securityReason = reason
		},
	}

	insp := &Inspector{
		AllowedHosts: []string{"allowed.example.com", "*.safe.net"},
	}

	done := make(chan struct {
		blocked bool
		reason  string
	}, 1)

	go func() {
		_, blocked, reason, _ := insp.Run(ctx, clientB, upA)
		done <- struct {
			blocked bool
			reason  string
		}{blocked, reason}
	}()

	// Client sends request for disallowed host
	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		req := "GET / HTTP/1.1\r\nHost: evil.attacker.com\r\n\r\n"
		_, _ = clientA.Write([]byte(req))

		var buf [512]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := clientA.Read(buf[:])
		_ = clientA.Close()

		if !strings.Contains(string(buf[:n]), "403 Forbidden") {
			t.Errorf("expected 403 Forbidden response, got: %s", string(buf[:n]))
		}
	}()

	select {
	case res := <-done:
		if !res.blocked {
			t.Errorf("expected host to be blocked, got blocked=false")
		}
		if securityAction != "blocked" {
			t.Errorf("expected securityAction 'blocked', got %q", securityAction)
		}
		if !strings.Contains(securityReason, "evil.attacker.com") {
			t.Errorf("expected securityReason to contain host, got %q", securityReason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test timed out")
	}
}
