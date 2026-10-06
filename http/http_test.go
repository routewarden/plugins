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

func TestHTTP_BlockedPathRegex(t *testing.T) {
	p := &Plugin{}
	rawInsp, err := p.CreateInspector(map[string]any{
		"blocked_paths": []any{
			`^/admin(/.*)?$`,
			`\.(env|git|bak|sql)$`,
		},
	})
	if err != nil {
		t.Fatalf("failed creating inspector: %v", err)
	}

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

	done := make(chan struct {
		blocked bool
		reason  string
	}, 1)

	go func() {
		_, blocked, reason, _ := rawInsp.Run(ctx, clientB, upA)
		done <- struct {
			blocked bool
			reason  string
		}{blocked, reason}
	}()

	// Client sends request to /admin/settings
	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		req := "GET /admin/settings HTTP/1.1\r\nHost: example.com\r\n\r\n"
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
			t.Errorf("expected path to be blocked, got blocked=false")
		}
		if securityAction != "blocked" {
			t.Errorf("expected securityAction 'blocked', got %q", securityAction)
		}
		if !strings.Contains(securityReason, "/admin/settings") {
			t.Errorf("expected securityReason to contain blocked path, got %q", securityReason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test timed out")
	}
}

func TestHTTP_BlockedHeadersRegex(t *testing.T) {
	p := &Plugin{}
	rawInsp, err := p.CreateInspector(map[string]any{
		"blocked_headers": map[string]any{
			"X-Forwarded-Host": ".*",
			"Authorization":    `(?i)^basic\s+.*`,
		},
	})
	if err != nil {
		t.Fatalf("failed creating inspector: %v", err)
	}

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

	done := make(chan struct {
		blocked bool
		reason  string
	}, 1)

	go func() {
		_, blocked, reason, _ := rawInsp.Run(ctx, clientB, upA)
		done <- struct {
			blocked bool
			reason  string
		}{blocked, reason}
	}()

	// Client sends request with disallowed Authorization header (Basic)
	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		req := "GET /api/data HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
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
			t.Errorf("expected header to be blocked, got blocked=false")
		}
		if securityAction != "blocked" {
			t.Errorf("expected securityAction 'blocked', got %q", securityAction)
		}
		if !strings.Contains(securityReason, "Authorization") {
			t.Errorf("expected securityReason to contain blocked header name, got %q", securityReason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test timed out")
	}
}

func TestHTTP_ValidateRegexConfig(t *testing.T) {
	p := &Plugin{}

	valid := map[string]any{
		"blocked_paths": []any{
			`^/admin(/.*)?$`,
			`\.(env|git)$`,
		},
		"blocked_headers": map[string]any{
			"User-Agent": `(?i)(sqlmap|nikto)`,
			"X-Deny":     `.*`,
		},
	}
	if err := p.ValidateConfig(valid); err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}

	invalidPathRegex := map[string]any{
		"blocked_paths": []any{`[invalid-regex`},
	}
	if err := p.ValidateConfig(invalidPathRegex); err == nil {
		t.Fatal("expected error for invalid blocked_paths regex, got nil")
	}

	invalidHeaderRegex := map[string]any{
		"blocked_headers": map[string]any{
			"User-Agent": `[unclosed(`,
		},
	}
	if err := p.ValidateConfig(invalidHeaderRegex); err == nil {
		t.Fatal("expected error for invalid blocked_headers regex, got nil")
	}
}

func TestHTTP_IPv6HostAndApexDomain(t *testing.T) {
	if !isHostAllowed("::1", []string{"::1"}) {
		t.Errorf("expected ::1 to be allowed")
	}
	if !isHostAllowed("example.com", []string{"*.example.com"}) {
		t.Errorf("expected apex domain example.com to match *.example.com")
	}
	if !isHostAllowed("sub.example.com", []string{"*.example.com"}) {
		t.Errorf("expected subdomain sub.example.com to match *.example.com")
	}
	if isHostAllowed("other.com", []string{"*.example.com"}) {
		t.Errorf("expected other.com to be disallowed")
	}
}

func TestHTTP_PathTraversalEscape(t *testing.T) {
	allowed := []string{"/api/*"}
	// Legitimate path
	if !isPathAllowed("/api/v1/users", allowed) {
		t.Errorf("expected /api/v1/users to be allowed")
	}
	// Path traversal attempt attempting to escape /api/*
	if isPathAllowed("/api/../.env", allowed) {
		t.Errorf("expected /api/../.env to be rejected as traversal escape")
	}
	if isPathAllowed("/api/../../etc/passwd", allowed) {
		t.Errorf("expected /api/../../etc/passwd to be rejected as traversal escape")
	}
	// Parent route without trailing slash matches wildcard rule
	if !isPathAllowed("/api", allowed) {
		t.Errorf("expected /api to match /api/*")
	}
}

func TestHTTP_AbsoluteURIHost(t *testing.T) {
	insp := &Inspector{
		AllowedHosts: []string{"allowed.example.com"},
	}

	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	done := make(chan struct {
		blocked bool
		reason  string
	}, 1)

	go func() {
		_, blocked, reason, _ := insp.Run(nil, clientB, upA)
		done <- struct {
			blocked bool
			reason  string
		}{blocked, reason}
	}()

	// Client sends absolute URI with evil.com host despite Host header saying allowed.example.com
	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		req := "GET http://evil.com/api/test HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n"
		_, _ = clientA.Write([]byte(req))

		var buf [512]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := clientA.Read(buf[:])
		_ = clientA.Close()

		if !strings.Contains(string(buf[:n]), "403 Forbidden") {
			t.Errorf("expected 403 Forbidden response for absolute URI host mismatch, got: %s", string(buf[:n]))
		}
	}()

	select {
	case res := <-done:
		if !res.blocked {
			t.Errorf("expected absolute URI evil.com to be blocked")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test timed out")
	}
}

