package ftp

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func TestFTPPlugin_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("ftp SelfTest failed: %v", err)
	}
}

func TestFTPPlugin_ManifestAndConfig(t *testing.T) {
	p := &Plugin{}
	m := p.Manifest()
	if m.Name != "ftp" {
		t.Errorf("expected ftp, got %s", m.Name)
	}

	if err := p.ValidateConfig(map[string]any{"max_auth_failures": 5}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	insp, err := p.CreateInspector(nil)
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}

func TestFTPPlugin_AuthTLS_BufferedHandover(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	p := &Plugin{}
	insp, err := p.CreateInspector(nil)
	if err != nil {
		t.Fatalf("CreateInspector: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, _, err := insp.Run(nil, clientB, upA)
		done <- err
	}()

	// Upstream server mock
	upErr := make(chan error, 1)
	go func() {
		// Send greeting
		_, _ = upB.Write([]byte("220 FTP Server ready\r\n"))

		// Read AUTH TLS
		buf := make([]byte, 128)
		n, err := upB.Read(buf)
		if err != nil {
			upErr <- err
			return
		}
		if string(buf[:n]) != "AUTH TLS\r\n" {
			upErr <- fmt.Errorf("unexpected command: %q", string(buf[:n]))
			return
		}

		// Reply with 234
		_, _ = upB.Write([]byte("234 Enabling TLS Connection\r\n"))

		// Read pipelined TLS client hello bytes
		expected := "SYNTHETIC_TLS_HELLO"
		tlsBuf := make([]byte, len(expected))
		if _, err := io.ReadFull(upB, tlsBuf); err != nil {
			upErr <- err
			return
		}
		if string(tlsBuf) != expected {
			upErr <- fmt.Errorf("unexpected TLS payload: %q", string(tlsBuf))
			return
		}
		upErr <- nil
	}()

	// Client: read greeting, send AUTH TLS + pipelined TLS payload
	var greetingBuf [64]byte
	n, err := clientA.Read(greetingBuf[:])
	if err != nil {
		t.Fatalf("client read greeting: %v", err)
	}
	if !strings.HasPrefix(string(greetingBuf[:n]), "220") {
		t.Fatalf("unexpected greeting: %s", string(greetingBuf[:n]))
	}

	// Send AUTH TLS and immediate TLS hello bytes
	_, _ = clientA.Write([]byte("AUTH TLS\r\nSYNTHETIC_TLS_HELLO"))

	// Read 234 response
	var respBuf [64]byte
	n, err = clientA.Read(respBuf[:])
	if err != nil {
		t.Fatalf("client read 234: %v", err)
	}
	if !strings.HasPrefix(string(respBuf[:n]), "234") {
		t.Fatalf("unexpected response: %s", string(respBuf[:n]))
	}

	select {
	case err := <-upErr:
		if err != nil {
			t.Fatalf("upstream error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream to receive buffered TLS hello")
	}
}

func TestFTPPlugin_NormalLoginAndQuit(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{}
	done := make(chan error, 1)

	go func() {
		_, _, _, err := insp.Run(nil, clientB, upA)
		done <- err
	}()

	// Upstream server mock
	go func() {
		_ = upB.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte("220 FTP Service Ready\r\n"))

		buf := make([]byte, 128)
		_, _ = upB.Read(buf) // USER
		_, _ = upB.Write([]byte("331 User name okay, need password.\r\n"))

		_, _ = upB.Read(buf) // PASS
		_, _ = upB.Write([]byte("230 User logged in, proceed.\r\n"))

		_, _ = upB.Read(buf) // QUIT
		_, _ = upB.Write([]byte("221 Service closing control connection.\r\n"))
		_ = upB.Close()
	}()

	// Client mock
	go func() {
		_ = clientA.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 128)
		_, _ = clientA.Read(buf) // Read 220

		_, _ = clientA.Write([]byte("USER testuser\r\n"))
		_, _ = clientA.Read(buf) // Read 331

		_, _ = clientA.Write([]byte("PASS secret123\r\n"))
		_, _ = clientA.Read(buf) // Read 230

		_, _ = clientA.Write([]byte("QUIT\r\n"))
		_, _ = clientA.Read(buf) // Read 221
		_ = clientA.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error during normal FTP session: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("normal FTP session timed out")
	}
}

func TestFTPPlugin_AuthFailureTriggersEvent(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	authFailureCalled := false
	var secAction, secReason string
	ctx := &sdk.DefaultContext{
		AuthFailureFunc: func() {
			authFailureCalled = true
		},
		SecurityFunc: func(action, reason string) {
			secAction = action
			secReason = reason
		},
	}

	insp := &Inspector{}
	done := make(chan error, 1)

	go func() {
		_, _, _, err := insp.Run(ctx, clientB, upA)
		done <- err
	}()

	// Upstream server mock: fails auth
	go func() {
		_ = upB.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte("220 Welcome\r\n"))

		buf := make([]byte, 128)
		_, _ = upB.Read(buf) // USER
		_, _ = upB.Write([]byte("331 Need pass\r\n"))

		_, _ = upB.Read(buf) // PASS
		_, _ = upB.Write([]byte("530 Login incorrect.\r\n"))

		_, _ = upB.Read(buf) // QUIT
		_, _ = upB.Write([]byte("221 Goodbye.\r\n"))
		_ = upB.Close()
	}()

	// Client mock
	go func() {
		_ = clientA.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 128)
		_, _ = clientA.Read(buf) // 220

		_, _ = clientA.Write([]byte("USER baduser\r\n"))
		_, _ = clientA.Read(buf) // 331

		_, _ = clientA.Write([]byte("PASS wrongpass\r\n"))
		_, _ = clientA.Read(buf) // 530

		_, _ = clientA.Write([]byte("QUIT\r\n"))
		_, _ = clientA.Read(buf) // 221
		_ = clientA.Close()
	}()

	select {
	case <-done:
		if !authFailureCalled {
			t.Errorf("expected OnAuthFailure to be called on 530 Login incorrect")
		}
		if secAction != "auth_failure" {
			t.Errorf("expected security event action 'auth_failure', got %q", secAction)
		}
		if secReason != "ftp_login_failed" {
			t.Errorf("expected security event reason 'ftp_login_failed', got %q", secReason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("auth failure test timed out")
	}
}

func TestFTPPlugin_MultilineGreeting(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{}
	done := make(chan error, 1)

	go func() {
		_, _, _, err := insp.Run(nil, clientB, upA)
		done <- err
	}()

	// Upstream sends 3-line RFC 959 multiline greeting
	go func() {
		_ = upB.SetDeadline(time.Now().Add(2 * time.Second))
		multiline := "220-Welcome to Corporate FTP Server\r\n220-All connections are monitored\r\n220 Service ready.\r\n"
		_, _ = upB.Write([]byte(multiline))

		buf := make([]byte, 128)
		_, _ = upB.Read(buf)
		_, _ = upB.Write([]byte("221 Closing.\r\n"))
		_ = upB.Close()
	}()

	// Client reads complete multiline greeting
	go func() {
		_ = clientA.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, _ := io.ReadFull(clientA, buf[:len("220-Welcome to Corporate FTP Server\r\n220-All connections are monitored\r\n220 Service ready.\r\n")])
		if !strings.Contains(string(buf[:n]), "All connections are monitored") {
			t.Errorf("multiline greeting not received properly: %q", string(buf[:n]))
		}

		_, _ = clientA.Write([]byte("QUIT\r\n"))
		_, _ = clientA.Read(buf)
		_ = clientA.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("multiline greeting test timed out")
	}
}

func TestFTP_SecurityBoundaries(t *testing.T) {
	t.Run("MaxAuthFailures_BlocksConnection", func(t *testing.T) {
		clientA, clientB := net.Pipe()
		defer clientA.Close()
		defer clientPeerClose(clientB)

		upA, upB := net.Pipe()
		defer upA.Close()
		defer clientPeerClose(upB)

		insp := &Inspector{MaxAuthFailures: 2}
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

		// Upstream server mock
		go func() {
			_, _ = upB.Write([]byte("220 Welcome\r\n"))
			buf := make([]byte, 128)
			for {
				n, err := upB.Read(buf)
				if err != nil {
					return
				}
				cmd := string(buf[:n])
				if strings.HasPrefix(cmd, "USER") {
					_, _ = upB.Write([]byte("331 Need pass\r\n"))
				} else if strings.HasPrefix(cmd, "PASS") {
					_, _ = upB.Write([]byte("530 Login incorrect.\r\n"))
				}
			}
		}()

		// Client
		buf := make([]byte, 256)
		_, _ = clientA.Read(buf) // 220

		// Fail 1
		_, _ = clientA.Write([]byte("USER user1\r\n"))
		_, _ = clientA.Read(buf) // 331
		_, _ = clientA.Write([]byte("PASS wrong1\r\n"))
		_, _ = clientA.Read(buf) // 530

		// Fail 2 - should trigger 421 and disconnect
		_, _ = clientA.Write([]byte("USER user1\r\n"))
		_, _ = clientA.Read(buf) // 331
		_, _ = clientA.Write([]byte("PASS wrong2\r\n"))

		n, _ := clientA.Read(buf)
		resp := string(buf[:n])
		if !strings.Contains(resp, "421 Too many authentication failures") {
			t.Errorf("expected 421 response on exceeding max auth failures, got: %s", resp)
		}

		res := <-done
		if !res.blocked {
			t.Errorf("expected connection to be marked blocked")
		}
	})

	t.Run("LineTooLong_Returns500", func(t *testing.T) {
		clientA, clientB := net.Pipe()
		defer clientA.Close()
		defer clientB.Close()

		upA, upB := net.Pipe()
		defer upA.Close()
		defer upB.Close()

		insp := &Inspector{}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _, _, _ = insp.Run(nil, clientB, upA)
		}()

		go func() {
			_, _ = upB.Write([]byte("220 Welcome\r\n"))
		}()

		buf := make([]byte, 128)
		_, _ = clientA.Read(buf) // 220

		oversized := strings.Repeat("B", 4100)
		go func() {
			_, _ = clientA.Write([]byte(oversized))
		}()

		n, _ := clientA.Read(buf)
		if !strings.HasPrefix(string(buf[:n]), "500") {
			t.Errorf("expected 500 Line too long, got: %s", string(buf[:n]))
		}

		_ = clientA.Close()
		_ = upA.Close()
		<-done
	})
}

func clientPeerClose(c net.Conn) {
	if c != nil {
		_ = c.Close()
	}
}



