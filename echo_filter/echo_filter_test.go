package echo_filter

import (
	"io"
	"net"
	"testing"
)

func TestEchoFilterPlugin_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("echo_filter SelfTest failed: %v", err)
	}
}

func TestEchoFilterPlugin_ManifestAndConfig(t *testing.T) {
	p := &Plugin{}
	m := p.Manifest()
	if m.Name != "echo_filter" {
		t.Errorf("expected echo_filter, got %s", m.Name)
	}

	cfg := map[string]any{"banned_keywords": []string{"DROP", "DELETE"}}
	if err := p.ValidateConfig(cfg); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	insp, err := p.CreateInspector(cfg)
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}

func TestEchoFilter_Run_AllowAndProxy(t *testing.T) {
	insp := &Inspector{BannedKeywords: []string{"MALWARE", "ATTACK"}}

	clientConn, proxyClient := net.Pipe()
	proxyUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyUpstream.Close()
	defer upstreamConn.Close()

	done := make(chan error, 1)
	go func() {
		_, blocked, _, err := insp.Run(nil, proxyClient, proxyUpstream)
		if blocked {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- err
	}()

	// Upstream reader and responder
	go func() {
		// Read initial chunk
		buf1 := make([]byte, 5)
		_, _ = io.ReadFull(upstreamConn, buf1)
		// Read second chunk (verifying subsequent stream is not closed by BufferedConn bug!)
		buf2 := make([]byte, 6)
		_, _ = io.ReadFull(upstreamConn, buf2)
		// Echo back
		_, _ = upstreamConn.Write(append(buf1, buf2...))
		_ = upstreamConn.Close()
	}()

	// Client sends initial chunk, then subsequent chunk
	_, _ = clientConn.Write([]byte("HELLO"))
	_, _ = clientConn.Write([]byte(" WORLD"))

	respBuf := make([]byte, 11)
	_, err := io.ReadFull(clientConn, respBuf)
	if err != nil {
		t.Fatalf("failed reading echoed response: %v", err)
	}
	if string(respBuf) != "HELLO WORLD" {
		t.Fatalf("expected 'HELLO WORLD', got %q", string(respBuf))
	}
	_ = clientConn.Close()

	<-done
}

func TestEchoFilter_Run_BlockedKeyword(t *testing.T) {
	insp := &Inspector{BannedKeywords: []string{"MALWARE", "ATTACK"}}

	clientConn, proxyClient := net.Pipe()
	proxyUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyUpstream.Close()
	defer upstreamConn.Close()

	done := make(chan bool, 1)
	go func() {
		_, blocked, reason, _ := insp.Run(nil, proxyClient, proxyUpstream)
		if !blocked || reason == "" {
			done <- false
			return
		}
		done <- true
	}()

	_, _ = clientConn.Write([]byte("contains malware inside payload"))
	resp := make([]byte, 256)
	n, _ := clientConn.Read(resp)
	if n == 0 {
		t.Fatalf("expected rejection response")
	}

	if !<-done {
		t.Fatalf("expected session to be marked as blocked")
	}
}
