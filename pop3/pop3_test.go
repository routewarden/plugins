package pop3

import (
	"io"
	"net"
	"strings"
	"testing"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func TestPluginManifest(t *testing.T) {
	p := &Plugin{}
	manifest := p.Manifest()

	if manifest.Name != "pop3" {
		t.Fatalf("expected plugin name 'pop3', got: %s", manifest.Name)
	}

	if len(manifest.Protocols) == 0 || manifest.Protocols[0] != "pop3" {
		t.Fatalf("expected protocol 'pop3', got: %v", manifest.Protocols)
	}
}

func TestPluginSelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest failed: %v", err)
	}
}

func TestPOP3_Run_AuthFailure(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	authFailed := false
	ctx := &sdk.DefaultContext{
		ServiceName:   "pop3-test",
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
		_, _ = upPeer.Write([]byte("+OK POP3 server ready\r\n"))
	}()

	// Client reads greeting
	greetBuf := make([]byte, 23)
	if _, err := io.ReadFull(clientPeer, greetBuf); err != nil {
		t.Fatalf("failed reading greeting: %v", err)
	}

	// Client sends PASS badpassword\r\n
	go func() {
		_, _ = clientPeer.Write([]byte("PASS badpassword\r\n"))
	}()

	// Upstream reads PASS and replies -ERR
	passBuf := make([]byte, 18)
	_, _ = io.ReadFull(upPeer, passBuf)
	go func() {
		_, _ = upPeer.Write([]byte("-ERR authentication failed\r\n"))
	}()

	// Client reads -ERR
	errBuf := make([]byte, 28)
	_, _ = io.ReadFull(clientPeer, errBuf)

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done

	if !authFailed {
		t.Errorf("expected AuthFailureFunc to be called on -ERR response to PASS")
	}
}

func TestPOP3_Run_NormalSessionAndQuit(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	insp := &Inspector{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, blocked, _, _ := insp.Run(nil, clientConn, upConn)
		if blocked {
			t.Errorf("expected clean session, got blocked")
		}
	}()

	// Upstream sends greeting
	go func() {
		_, _ = upPeer.Write([]byte("+OK POP3 server ready\r\n"))
	}()

	// Client reads greeting
	var buf [64]byte
	n, _ := clientPeer.Read(buf[:])
	if !strings.HasPrefix(string(buf[:n]), "+OK") {
		t.Fatalf("unexpected greeting: %s", string(buf[:n]))
	}

	// Client sends QUIT
	go func() {
		_, _ = clientPeer.Write([]byte("QUIT\r\n"))
	}()

	// Upstream reads QUIT and sends goodbye
	upN, _ := upPeer.Read(buf[:])
	if string(buf[:upN]) != "QUIT\r\n" {
		t.Errorf("expected QUIT, got %s", string(buf[:upN]))
	}
	go func() {
		_, _ = upPeer.Write([]byte("+OK Bye\r\n"))
	}()

	// Client reads goodbye
	n, _ = clientPeer.Read(buf[:])
	if !strings.HasPrefix(string(buf[:n]), "+OK Bye") {
		t.Errorf("expected +OK Bye, got %s", string(buf[:n]))
	}

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}

func TestPOP3_ValidateConfig(t *testing.T) {
	p := &Plugin{}
	if err := p.ValidateConfig(nil); err != nil {
		t.Errorf("nil config rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"max_auth_failures": 5}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"max_auth_failures": "invalid"}); err == nil {
		t.Errorf("expected error for non-int max_auth_failures")
	}
}
