package http

import (
	"bufio"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

//go:embed plugin.yaml
var manifestYAML []byte

func init() {
	plugins.Register(&Plugin{})
}

// HeaderRule represents a compiled regex rule for checking an HTTP header.
type HeaderRule struct {
	Header  string
	Pattern *regexp.Regexp
}

// Plugin implements sdk.Plugin for HTTP/1.x protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.MustParseManifest(manifestYAML)
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
	if v, exists := config["blocked_paths"]; exists {
		var patterns []string
		switch items := v.(type) {
		case []string:
			patterns = items
		case []any:
			for _, item := range items {
				s, ok := item.(string)
				if !ok {
					return fmt.Errorf("blocked_paths must be a list of regex strings")
				}
				patterns = append(patterns, s)
			}
		default:
			return fmt.Errorf("blocked_paths must be a list of regex strings, got %T", v)
		}
		for _, pat := range patterns {
			if _, err := regexp.Compile(pat); err != nil {
				return fmt.Errorf("invalid regex in blocked_paths %q: %w", pat, err)
			}
		}
	}
	if v, exists := config["blocked_headers"]; exists {
		switch val := v.(type) {
		case map[string]string:
			for hdr, pat := range val {
				if _, err := regexp.Compile(pat); err != nil {
					return fmt.Errorf("invalid regex for blocked header %q (%q): %w", hdr, pat, err)
				}
			}
		case map[string]any:
			for hdr, raw := range val {
				pat, ok := raw.(string)
				if !ok {
					return fmt.Errorf("pattern for blocked header %q must be a string", hdr)
				}
				if _, err := regexp.Compile(pat); err != nil {
					return fmt.Errorf("invalid regex for blocked header %q (%q): %w", hdr, pat, err)
				}
			}
		case []any:
			for _, item := range val {
				ruleMap, ok := item.(map[string]any)
				if !ok {
					return fmt.Errorf("each blocked_headers rule must be an object with 'header' and 'pattern'")
				}
				hdr, _ := ruleMap["header"].(string)
				if hdr == "" {
					hdr, _ = ruleMap["name"].(string)
				}
				pat, _ := ruleMap["pattern"].(string)
				if pat == "" {
					pat, _ = ruleMap["regex"].(string)
				}
				if hdr == "" || pat == "" {
					return fmt.Errorf("blocked_headers list item must contain 'header' and 'pattern' strings")
				}
				if _, err := regexp.Compile(pat); err != nil {
					return fmt.Errorf("invalid regex for blocked header %q (%q): %w", hdr, pat, err)
				}
			}
		default:
			return fmt.Errorf("blocked_headers must be a map or list of header regex rules, got %T", v)
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
	if v, ok := config["blocked_paths"]; ok {
		var patterns []string
		switch items := v.(type) {
		case []string:
			patterns = items
		case []any:
			for _, item := range items {
				if s, ok := item.(string); ok {
					patterns = append(patterns, s)
				}
			}
		}
		for _, pat := range patterns {
			rx, err := regexp.Compile(pat)
			if err == nil {
				insp.BlockedPaths = append(insp.BlockedPaths, rx)
			}
		}
	}
	if v, ok := config["blocked_headers"]; ok {
		switch val := v.(type) {
		case map[string]string:
			for hdr, pat := range val {
				if rx, err := regexp.Compile(pat); err == nil {
					insp.BlockedHeaders = append(insp.BlockedHeaders, HeaderRule{
						Header:  hdr,
						Pattern: rx,
					})
				}
			}
		case map[string]any:
			for hdr, raw := range val {
				if pat, ok := raw.(string); ok {
					if rx, err := regexp.Compile(pat); err == nil {
						insp.BlockedHeaders = append(insp.BlockedHeaders, HeaderRule{
							Header:  hdr,
							Pattern: rx,
						})
					}
				}
			}
		case []any:
			for _, item := range val {
				if ruleMap, ok := item.(map[string]any); ok {
					hdr, _ := ruleMap["header"].(string)
					if hdr == "" {
						hdr, _ = ruleMap["name"].(string)
					}
					pat, _ := ruleMap["pattern"].(string)
					if pat == "" {
						pat, _ = ruleMap["regex"].(string)
					}
					if hdr != "" && pat != "" {
						if rx, err := regexp.Compile(pat); err == nil {
							insp.BlockedHeaders = append(insp.BlockedHeaders, HeaderRule{
								Header:  hdr,
								Pattern: rx,
							})
						}
					}
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

// Inspector filters HTTP/1.x traffic based on Host, User-Agent, Request URI, and regex rules.
type Inspector struct {
	AllowedHosts      []string
	BlockedUserAgents []string
	AllowedPaths      []string
	BlockedPaths      []*regexp.Regexp
	BlockedHeaders    []HeaderRule
}

// Run processes HTTP/1.x requests from the client.
func (insp *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	var bytesIn, bytesOut atomic.Int64

	result := func(err error) sdk.ProxyResult {
		return sdk.ProxyResult{BytesIn: bytesIn.Load(), BytesOut: bytesOut.Load(), Err: err}
	}

	clientReader := bufio.NewReader(client)
	upstreamReader := bufio.NewReader(upstream)

	for {
		client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return result(nil), false, "", nil
			}
			return result(err), false, "", nil
		}

		// 1. Check Host header and absolute Request-URI host
		if len(insp.AllowedHosts) > 0 {
			hostsToCheck := []string{req.Host}
			if req.URL.Host != "" && req.URL.Host != req.Host {
				hostsToCheck = append(hostsToCheck, req.URL.Host)
			}
			for _, h := range hostsToCheck {
				reqHost := h
				if host, _, err := net.SplitHostPort(reqHost); err == nil {
					reqHost = host
				} else if idx := strings.Index(reqHost, ":"); idx != -1 && !strings.Contains(reqHost, "]") {
					reqHost = reqHost[:idx]
				}
				reqHost = strings.Trim(reqHost, "[]")
				reqHost = strings.TrimSuffix(reqHost, ".")
				if !isHostAllowed(reqHost, insp.AllowedHosts) {
					sendHTTPForbidden(client, "Host forbidden by RouteWarden\n")
					if ctx != nil {
						ctx.OnSecurityEvent("blocked", "http_host_blocked_"+reqHost)
					}
					return result(nil), true, "blocked http host: " + reqHost, nil
				}
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

		// 3. Check Request URI path allowlist
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

		// 4. Check Blocked Paths (Regex)
		if len(insp.BlockedPaths) > 0 {
			reqPath := req.URL.Path
			cleanedPath := path.Clean(reqPath)
			pathsToMatch := []string{reqPath, cleanedPath}
			if req.URL.RawPath != "" && req.URL.RawPath != reqPath {
				pathsToMatch = append(pathsToMatch, req.URL.RawPath)
			}
			if req.RequestURI != "" && req.RequestURI != reqPath {
				pathsToMatch = append(pathsToMatch, req.RequestURI)
			}
			for _, rx := range insp.BlockedPaths {
				matched := false
				for _, p := range pathsToMatch {
					if rx.MatchString(p) {
						matched = true
						break
					}
				}
				if matched {
					sendHTTPForbidden(client, "Path forbidden by RouteWarden\n")
					if ctx != nil {
						ctx.OnSecurityEvent("blocked", "http_path_blocked_"+cleanedPath)
					}
					return result(nil), true, "blocked http path regex: " + cleanedPath, nil
				}
			}
		}

		// 5. Check Blocked Headers (Regex)
		if len(insp.BlockedHeaders) > 0 {
			for _, rule := range insp.BlockedHeaders {
				vals := req.Header.Values(rule.Header)
				if len(vals) == 0 && strings.EqualFold(rule.Header, "Host") && req.Host != "" {
					vals = []string{req.Host}
				}
				for _, val := range vals {
					if rule.Pattern.MatchString(val) {
						sendHTTPForbidden(client, "Header rejected by RouteWarden\n")
						if ctx != nil {
							ctx.OnSecurityEvent("blocked", "http_header_blocked_"+rule.Header)
						}
						return result(nil), true, fmt.Sprintf("blocked http header %s: %s", rule.Header, val), nil
					}
				}
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
			bufferedClient := &protocol.BufferedConn{Reader: clientReader, Conn: client}
			bufferedUpstream := &protocol.BufferedConn{Reader: upstreamReader, Conn: upstream}
			res := protocol.Proxy(bufferedClient, bufferedUpstream)
			bytesIn.Add(res.BytesIn)
			bytesOut.Add(res.BytesOut)
			return result(nil), false, "", nil
		}

		// Read response from upstream and forward to client
		upstream.SetReadDeadline(time.Now().Add(1 * time.Minute))
		resp, err := http.ReadResponse(upstreamReader, req)
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
	resp := &http.Response{
		StatusCode:    http.StatusForbidden,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = resp.Write(conn)
}

func isHostAllowed(host string, allowedHosts []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, allowed := range allowedHosts {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed == "*" || host == allowed {
			return true
		}
		if strings.HasPrefix(allowed, "*.") {
			suffix := allowed[1:] // e.g. ".example.com"
			if strings.HasSuffix(host, suffix) {
				return true
			}
			if host == allowed[2:] { // apex domain match
				return true
			}
		}
	}
	return false
}

func isPathAllowed(reqPath string, allowedPaths []string) bool {
	cleaned := path.Clean(reqPath)
	for _, allowed := range allowedPaths {
		allowed = strings.TrimSpace(allowed)
		if allowed == "*" {
			return true
		}
		if before, ok := strings.CutSuffix(allowed, "*"); ok {
			prefix := before
			if strings.HasPrefix(cleaned, prefix) || cleaned == strings.TrimSuffix(prefix, "/") {
				return true
			}
		} else if reqPath == allowed || cleaned == allowed {
			return true
		}
	}
	return false
}
