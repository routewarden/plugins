package ssh

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func TestPluginManifest(t *testing.T) {
	p := &Plugin{}
	manifest := p.Manifest()

	if manifest.Name != "ssh" {
		t.Fatalf("expected plugin name 'ssh', got: %s", manifest.Name)
	}

	if len(manifest.Protocols) == 0 || manifest.Protocols[0] != "ssh" {
		t.Fatalf("expected protocol 'ssh', got: %v", manifest.Protocols)
	}
}

func TestPluginSelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest failed: %v", err)
	}
}

func TestSSH_Run_InvalidClientBanner(t *testing.T) {
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
		_, blocked, reason, err := insp.Run(nil, clientConn, upConn)
		if !blocked {
			t.Errorf("expected blocked=true for invalid banner")
		}
		if err == nil {
			t.Errorf("expected error for invalid banner")
		}
		if !strings.Contains(reason, "invalid SSH") {
			t.Errorf("expected reason to mention invalid SSH, got: %s", reason)
		}
	}()

	// Client sends HTTP request instead of SSH banner
	go func() {
		_, _ = clientPeer.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	}()

	// Client drains all rejection bytes until server closes
	var readAllBuf bytes.Buffer
	_, _ = io.Copy(&readAllBuf, clientPeer)
	resp := readAllBuf.String()
	if !strings.HasPrefix(resp, "SSH-2.0-RouteWarden") {
		t.Errorf("expected RouteWarden banner in rejection, got: %s", resp)
	}

	<-done
}

func TestSSH_Run_SSH1Rejected(t *testing.T) {
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
		_, blocked, reason, _ := insp.Run(nil, clientConn, upConn)
		if !blocked {
			t.Errorf("expected blocked=true for SSH-1.x")
		}
		if !strings.Contains(reason, "SSH-1.x rejected") {
			t.Errorf("expected SSH-1.x rejection, got: %s", reason)
		}
	}()

	go func() {
		_, _ = clientPeer.Write([]byte("SSH-1.5-OpenSSH_3.8\r\n"))
	}()

	var readAllBuf bytes.Buffer
	_, _ = io.Copy(&readAllBuf, clientPeer)

	<-done
}

func TestSSH_Run_ValidSSH2AndProxy(t *testing.T) {
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
			t.Errorf("expected allowed SSH-2.0 connection")
		}
	}()

	// Client sends SSH-2.0 banner
	go func() {
		_, _ = clientPeer.Write([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
	}()

	// Upstream reads client banner forwarded by inspector
	var buf [64]byte
	n, err := upPeer.Read(buf[:])
	if err != nil {
		t.Fatalf("upstream failed reading banner: %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "SSH-2.0-OpenSSH_8.9") {
		t.Errorf("upstream received %s", string(buf[:n]))
	}

	// Upstream sends server banner
	go func() {
		_, _ = upPeer.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
	}()

	// Client reads server banner
	clientN, err := clientPeer.Read(buf[:])
	if err != nil {
		t.Fatalf("client failed reading banner: %v", err)
	}
	if !strings.HasPrefix(string(buf[:clientN]), "SSH-2.0-OpenSSH_9.0") {
		t.Errorf("client received %s", string(buf[:clientN]))
	}

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}

func TestSSH_Run_AuthFailureMonitored(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	authFailed := false
	ctx := &sdk.DefaultContext{
		ServiceName:   "ssh-test",
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

	// Client sends banner
	go func() {
		_, _ = clientPeer.Write([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
	}()

	var buf [64]byte
	_, _ = upPeer.Read(buf[:])

	// Upstream sends SSH packet with message type 51 (SSH_MSG_USERAUTH_FAILURE)
	// SSH packet layout: uint32 packet_length, uint8 padding_length, byte msgType, padding...
	// Total = 4 + packet_length
	// Let packet_length = 12 (1 byte padding_len + 1 byte msgType + 10 bytes payload/padding)
	failPkt := []byte{
		0x00, 0x00, 0x00, 0x0C, // packet_length = 12
		0x04,                   // padding_length = 4
		51,                     // SSH_MSG_USERAUTH_FAILURE
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // payload
		0x00, 0x00, 0x00, 0x00, // padding (4 bytes)
	}
	go func() {
		_, _ = upPeer.Write(failPkt)
	}()

	// Client reads the failure packet
	readPkt := make([]byte, len(failPkt))
	_, _ = io.ReadFull(clientPeer, readPkt)

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done

	if !authFailed {
		t.Errorf("expected AuthFailureFunc to be called when upstream sends SSH_MSG_USERAUTH_FAILURE (type 51)")
	}
}

func TestSSH_ValidateConfig(t *testing.T) {
	p := &Plugin{}
	if err := p.ValidateConfig(nil); err != nil {
		t.Errorf("nil config rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"max_auth_tries": 3}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"max_auth_tries": "not-an-int"}); err == nil {
		t.Errorf("expected error for non-int max_auth_tries")
	}
}
