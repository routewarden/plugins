package http

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

func init() {
	plugins.Register(&Plugin{})
}

// Plugin implements sdk.Plugin for HTTP/1.x protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "http",
		Version:     "1.0.0",
		Description: "HTTP/1.x protocol inspector with Host header filtering, User-Agent blocking, and path allowlists",
		Author:      "RouteWarden Team",
		Protocols:   []string{"http"},
	}
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	if v, exists := config["allowed_hosts"]; exists {
		switch items := v.(type) {
		case []string:
		case []any:
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("allowed_hosts must be a list of strings")
				}
			}
		default:
			return fmt.Errorf("allowed_hosts must be a list of strings, got %T", v)
		}
	}
	if v, exists := config["blocked_user_agents"]; exists {
		switch items := v.(type) {
		case []string:
		case []any:
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("blocked_user_agents must be a list of strings")
				}
			}
		default:
			return fmt.Errorf("blocked_user_agents must be a list of strings, got %T", v)
		}
	}
	if v, exists := config["allowed_paths"]; exists {
		switch items := v.(type) {
		case []string:
		case []any:
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("allowed_paths must be a list of strings")
				}
			}
		default:
			return fmt.Errorf("allowed_paths must be a list of strings, got %T", v)
		}
	}
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	insp := &Inspector{}
	if config == nil {
		return insp, nil
	}
	if v, ok := config["allowed_hosts"]; ok {
		switch items := v.(type) {
		case []string:
			insp.AllowedHosts = items
		case []any:
			for _, item := range items {
				if s, ok := item.(string); ok {
					insp.AllowedHosts = append(insp.AllowedHosts, s)
				}
			}
		}
	}
	if v, ok := config["blocked_user_agents"]; ok {
		switch items := v.(type) {
		case []string:
			insp.BlockedUserAgents = items
		case []any:
			for _, item := range items {
				if s, ok := item.(string); ok {
					insp.BlockedUserAgents = append(insp.BlockedUserAgents, s)
				}
			}
		}
	}
	if v, ok := config["allowed_paths"]; ok {
		switch items := v.(type) {
		case []string:
			insp.AllowedPaths = items
		case []any:
			for _, item := range items {
				if s, ok := item.(string); ok {
					insp.AllowedPaths = append(insp.AllowedPaths, s)
				}
			}
		}
	}
	return insp, nil
}

// SelfTest verifies that a blocked User-Agent generates a 403 Forbidden response and triggers SecurityFunc.
func (p *Plugin) SelfTest() error {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	var blocked bool
	var mu sync.Mutex

	ctx := &sdk.DefaultContext{
		ServiceName:   "selftest-http",
		ClientAddress: "127.0.0.1",
		SecurityFunc: func(action, reason string) {
			if action == "blocked" {
				mu.Lock()
				blocked = true
				mu.Unlock()
			}
		},
	}

	insp := &Inspector{
		BlockedUserAgents: []string{"sqlmap"},
	}

	done := make(chan error, 1)
	go func() {
		_, wasBlocked, _, err := insp.Run(ctx, clientB, upA)
		if !wasBlocked {
			err = errors.New("self-test failed: malicious User-Agent was not blocked")
		}
		done <- err
	}()

	// Synthetic client sends HTTP request with blocked User-Agent
	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		req := "GET /api/data HTTP/1.1\r\nHost: example.com\r\nUser-Agent: sqlmap/1.5\r\n\r\n"
		_, _ = clientA.Write([]byte(req))

		var resp [512]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := clientA.Read(resp[:])
		_ = clientA.Close()

		if n > 0 && !strings.Contains(string(resp[:n]), "403 Forbidden") {
			// Did not receive 403
		}
	}()

	select {
	case err := <-done:
		if err != nil {
			return err
		}
		mu.Lock()
		b := blocked
		mu.Unlock()
		if !b {
			return errors.New("self-test failed: security event was not triggered")
		}
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("self-test timed out after 3s")
	}
}

// Inspector filters HTTP/1.x traffic based on Host, User-Agent, and Request URI.
type Inspector struct {
	AllowedHosts      []string
	BlockedUserAgents []string
	AllowedPaths      []string
}

// Run processes HTTP/1.x requests from the client.
func (insp *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	var bytesIn, bytesOut atomic.Int64

	result := func(err error) sdk.ProxyResult {
		return sdk.ProxyResult{BytesIn: bytesIn.Load(), BytesOut: bytesOut.Load(), Err: err}
	}

	clientReader := bufio.NewReader(client)

	for {
		client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return result(nil), false, "", nil
			}
			return result(err), false, "", nil
		}

		// 1. Check Host header
		if len(insp.AllowedHosts) > 0 {
			reqHost := req.Host
			if idx := strings.Index(reqHost, ":"); idx != -1 {
				reqHost = reqHost[:idx]
			}
			if !isHostAllowed(reqHost, insp.AllowedHosts) {
				sendHTTPForbidden(client, "Host forbidden by RouteWarden\n")
				if ctx != nil {
					ctx.OnSecurityEvent("blocked", "http_host_blocked_"+reqHost)
				}
				return result(nil), true, "blocked http host: " + reqHost, nil
			}
		}

		// 2. Check User-Agent header
		ua := req.UserAgent()
		if len(insp.BlockedUserAgents) > 0 && ua != "" {
			uaLower := strings.ToLower(ua)
			for _, blockedUA := range insp.BlockedUserAgents {
				if strings.Contains(uaLower, strings.ToLower(blockedUA)) {
					sendHTTPForbidden(client, "User-Agent blocked by RouteWarden\n")
					if ctx != nil {
						ctx.OnSecurityEvent("blocked", "http_user_agent_blocked_"+blockedUA)
					}
					return result(nil), true, "blocked http user-agent: " + ua, nil
				}
			}
		}

		// 3. Check Request URI path
		if len(insp.AllowedPaths) > 0 {
			reqPath := req.URL.Path
			if !isPathAllowed(reqPath, insp.AllowedPaths) {
				sendHTTPForbidden(client, "Path forbidden by RouteWarden\n")
				if ctx != nil {
					ctx.OnSecurityEvent("blocked", "http_path_blocked_"+reqPath)
				}
				return result(nil), true, "blocked http path: " + reqPath, nil
			}
		}

		// Forward valid request to upstream
		upstream.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if err := req.Write(upstream); err != nil {
			return result(err), false, "", nil
		}

		// If WebSocket upgrade or Connection: Upgrade, switch to bidirectional tunnel
		if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
			client.SetDeadline(time.Time{})
			upstream.SetDeadline(time.Time{})
			res := protocol.Proxy(client, upstream)
			bytesIn.Add(res.BytesIn)
			bytesOut.Add(res.BytesOut)
			return result(nil), false, "", nil
		}

		// Read response from upstream and forward to client
		upstream.SetReadDeadline(time.Now().Add(1 * time.Minute))
		resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
		if err != nil {
			return result(err), false, "", nil
		}

		client.SetWriteDeadline(time.Now().Add(1 * time.Minute))
		if err := resp.Write(client); err != nil {
			return result(err), false, "", nil
		}

		if req.Close || resp.Close {
			return result(nil), false, "", nil
		}
	}
}

func sendHTTPForbidden(conn net.Conn, body string) {
	resp := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte(resp))
}

func isHostAllowed(host string, allowedHosts []string) bool {
	host = strings.ToLower(host)
	for _, allowed := range allowedHosts {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if strings.HasPrefix(allowed, "*.") {
			suffix := allowed[1:] // e.g. ".example.com"
			if strings.HasSuffix(host, suffix) {
				return true
			}
		} else if host == allowed {
			return true
		}
	}
	return false
}

func isPathAllowed(path string, allowedPaths []string) bool {
	for _, allowed := range allowedPaths {
		allowed = strings.TrimSpace(allowed)
		if strings.HasSuffix(allowed, "*") {
			prefix := strings.TrimSuffix(allowed, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		} else if path == allowed {
			return true
		}
	}
	return false
}
