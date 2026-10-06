package redis

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
)

func TestRedisPlugin_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("redis SelfTest failed: %v", err)
	}
}

func TestRedisPlugin_ManifestAndConfig(t *testing.T) {
	p := &Plugin{}
	m := p.Manifest()
	if m.Name != "redis" {
		t.Errorf("expected redis, got %s", m.Name)
	}

	if err := p.ValidateConfig(map[string]any{"blocked_commands": []string{"FLUSHALL", "CONFIG"}}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	insp, err := p.CreateInspector(map[string]any{"blocked_commands": []any{"FLUSHALL"}})
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}

type mockSDKContext struct {
	authFailures   int
	securityEvents []string
}

func (m *mockSDKContext) Context() context.Context { return context.Background() }
func (m *mockSDKContext) Service() string          { return "redis" }
func (m *mockSDKContext) ClientIP() string         { return "192.168.1.100" }
func (m *mockSDKContext) OnAuthFailure()           { m.authFailures++ }
func (m *mockSDKContext) OnSecurityEvent(action, reason string) {
	m.securityEvents = append(m.securityEvents, action+":"+reason)
}

func TestRedis_Run_AllowedCommandAndProxy(t *testing.T) {
	insp := NewInspector([]string{"FLUSHALL", "CONFIG"})

	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, blocked, reason, _ := insp.Run(nil, clientConn, upConn)
		if blocked {
			t.Errorf("expected command to be allowed, got blocked: %s", reason)
		}
	}()

	// 1. Client sends PING\r\n
	go func() {
		_, _ = clientPeer.Write([]byte("PING\r\n"))
	}()

	// Upstream receives PING\r\n and responds +PONG\r\n
	buf := make([]byte, 6)
	if _, err := io.ReadFull(upPeer, buf); err != nil {
		t.Fatalf("upstream failed reading: %v", err)
	}
	if string(buf) != "PING\r\n" {
		t.Errorf("upstream expected 'PING\\r\\n', got %q", string(buf))
	}
	go func() {
		_, _ = upPeer.Write([]byte("+PONG\r\n"))
	}()

	// Client receives +PONG\r\n
	clientBuf := make([]byte, 7)
	if _, err := io.ReadFull(clientPeer, clientBuf); err != nil {
		t.Fatalf("client failed reading pong: %v", err)
	}
	if string(clientBuf) != "+PONG\r\n" {
		t.Errorf("client expected '+PONG\\r\\n', got %q", string(clientBuf))
	}

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}

func TestRedis_Run_BlockedCommand(t *testing.T) {
	insp := NewInspector([]string{"FLUSHALL", "CONFIG"})
	mockCtx := &mockSDKContext{}

	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, blocked, reason, _ := insp.Run(mockCtx, clientConn, upConn)
		if !blocked {
			t.Errorf("expected blocked=true for FLUSHALL")
		}
		if reason != "blocked redis command: FLUSHALL" {
			t.Errorf("unexpected reason: %s", reason)
		}
	}()

	// Client sends RESP array for FLUSHALL: *1\r\n$8\r\nFLUSHALL\r\n
	cmd := "*1\r\n$8\r\nFLUSHALL\r\n"
	go func() {
		_, _ = clientPeer.Write([]byte(cmd))
	}()

	// Client should immediately receive error from inspector
	respBuf := make([]byte, 256)
	n, err := clientPeer.Read(respBuf)
	if err != nil {
		t.Fatalf("failed reading error response: %v", err)
	}
	respStr := string(respBuf[:n])
	if !strings.Contains(respStr, "ERR command 'FLUSHALL' is blocked") {
		t.Errorf("unexpected error message: %s", respStr)
	}

	<-done

	if len(mockCtx.securityEvents) == 0 {
		t.Errorf("expected security event for blocked command")
	}
}

func TestRedis_Run_AuthFailureTrigger(t *testing.T) {
	insp := NewInspector([]string{"FLUSHALL"})
	mockCtx := &mockSDKContext{}

	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _, _ = insp.Run(mockCtx, clientConn, upConn)
	}()

	// Client sends AUTH badpass
	go func() {
		_, _ = clientPeer.Write([]byte("AUTH badpass\r\n"))
	}()

	// Upstream reads AUTH and replies -WRONGPASS
	buf := make([]byte, 256)
	n, _ := upPeer.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "AUTH") {
		t.Errorf("expected upstream to receive AUTH command, got %s", string(buf[:n]))
	}

	go func() {
		_, _ = upPeer.Write([]byte("-WRONGPASS invalid username-password pair\r\n"))
	}()

	// Client reads response
	respBuf := make([]byte, 256)
	_, _ = clientPeer.Read(respBuf)

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done

	if mockCtx.authFailures != 1 {
		t.Errorf("expected 1 auth failure recorded, got %d", mockCtx.authFailures)
	}
}

func TestRedis_Run_SubscribeStreaming(t *testing.T) {
	insp := NewInspector([]string{"FLUSHALL"})

	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _, _ = insp.Run(nil, clientConn, upConn)
	}()

	// Client sends SUBSCRIBE alerts\r\n
	subCmd := "*2\r\n$9\r\nSUBSCRIBE\r\n$6\r\nalerts\r\n"
	go func() {
		_, _ = clientPeer.Write([]byte(subCmd))
	}()

	// Upstream receives command
	upBuf := make([]byte, len(subCmd))
	if _, err := io.ReadFull(upPeer, upBuf); err != nil {
		t.Fatalf("upstream failed reading: %v", err)
	}
	if string(upBuf) != subCmd {
		t.Errorf("expected %q, got %q", subCmd, string(upBuf))
	}

	// Upstream sends initial subscription confirmation: *3\r\n$9\r\nsubscribe\r\n$6\r\nalerts\r\n:1\r\n
	subConfirm := "*3\r\n$9\r\nsubscribe\r\n$6\r\nalerts\r\n:1\r\n"
	go func() {
		_, _ = upPeer.Write([]byte(subConfirm))
	}()

	// Client receives confirmation
	clientBuf := make([]byte, len(subConfirm))
	if _, err := io.ReadFull(clientPeer, clientBuf); err != nil {
		t.Fatalf("client failed reading confirmation: %v", err)
	}
	if string(clientBuf) != subConfirm {
		t.Errorf("expected %q, got %q", subConfirm, string(clientBuf))
	}

	// Now in pub/sub streaming mode! Upstream pushes a message asynchronously WITHOUT client sending a command
	pushMsg := "*3\r\n$7\r\nmessage\r\n$6\r\nalerts\r\n$5\r\nfire!\r\n"
	go func() {
		_, _ = upPeer.Write([]byte(pushMsg))
	}()

	// Client receives push message directly
	msgBuf := make([]byte, len(pushMsg))
	if _, err := io.ReadFull(clientPeer, msgBuf); err != nil {
		t.Fatalf("client failed reading async push: %v", err)
	}
	if string(msgBuf) != pushMsg {
		t.Errorf("expected push message %q, got %q", pushMsg, string(msgBuf))
	}

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}

