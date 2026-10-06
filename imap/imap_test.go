package imap

import (
	"net"
	"strings"
	"testing"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func TestPluginManifest(t *testing.T) {
	p := &Plugin{}
	manifest := p.Manifest()

	if manifest.Name != "imap" {
		t.Fatalf("expected plugin name 'imap', got: %s", manifest.Name)
	}

	if len(manifest.Protocols) == 0 || manifest.Protocols[0] != "imap" {
		t.Fatalf("expected protocol 'imap', got: %v", manifest.Protocols)
	}
}

func TestPluginSelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest failed: %v", err)
	}
}

func TestIMAP_Run_AuthFailure(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	authFailed := false
	ctx := &sdk.DefaultContext{
		ServiceName:   "imap-test",
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
		_, _ = upPeer.Write([]byte("* OK IMAP4rev1 server ready\r\n"))
	}()

	var buf [128]byte
	n, _ := clientPeer.Read(buf[:])
	if !strings.HasPrefix(string(buf[:n]), "* OK") {
		t.Fatalf("unexpected greeting: %s", string(buf[:n]))
	}

	// Client sends tagged LOGIN
	go func() {
		_, _ = clientPeer.Write([]byte("A01 LOGIN user wrongpass\r\n"))
	}()

	// Upstream reads LOGIN and replies tagged NO
	upN, _ := upPeer.Read(buf[:])
	if !strings.Contains(string(buf[:upN]), "LOGIN") {
		t.Errorf("expected LOGIN, got %s", string(buf[:upN]))
	}
	go func() {
		_, _ = upPeer.Write([]byte("A01 NO [AUTHENTICATIONFAILED] Invalid credentials\r\n"))
	}()

	// Client reads tagged NO
	_, _ = clientPeer.Read(buf[:])

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done

	if !authFailed {
		t.Errorf("expected AuthFailureFunc to be called on tagged NO response to LOGIN")
	}
}

func TestIMAP_Run_SuccessAndLogout(t *testing.T) {
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
		_, _ = upPeer.Write([]byte("* OK IMAP4rev1 server ready\r\n"))
	}()

	var buf [128]byte
	_, _ = clientPeer.Read(buf[:])

	// Client sends LOGOUT
	go func() {
		_, _ = clientPeer.Write([]byte("A02 LOGOUT\r\n"))
	}()

	// Upstream reads LOGOUT and replies
	upN, _ := upPeer.Read(buf[:])
	if !strings.Contains(string(buf[:upN]), "LOGOUT") {
		t.Errorf("expected LOGOUT, got %s", string(buf[:upN]))
	}
	go func() {
		_, _ = upPeer.Write([]byte("A02 OK LOGOUT completed\r\n"))
	}()

	// Client reads completion
	_, _ = clientPeer.Read(buf[:])

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}

func TestIMAP_ValidateConfig(t *testing.T) {
	p := &Plugin{}
	if err := p.ValidateConfig(nil); err != nil {
		t.Errorf("nil config rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"max_auth_failures": 3}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"max_auth_failures": "invalid"}); err == nil {
		t.Errorf("expected error for non-int max_auth_failures")
	}
}

func TestIMAP_SecurityBoundaries(t *testing.T) {
	t.Run("MaxAuthFailures_BlocksConnection", func(t *testing.T) {
		clientA, clientB := net.Pipe()
		defer clientA.Close()
		defer clientB.Close()

		upA, upB := net.Pipe()
		defer upA.Close()
		defer upB.Close()

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

		// Upstream mock
		go func() {
			_, _ = upB.Write([]byte("* OK Dovecot ready\r\n"))
			buf := make([]byte, 256)
			for {
				n, err := upB.Read(buf)
				if err != nil {
					return
				}
				parts := strings.Fields(string(buf[:n]))
				if len(parts) >= 2 && strings.ToUpper(parts[1]) == "LOGIN" {
					_, _ = upB.Write([]byte(parts[0] + " NO Authentication failed\r\n"))
				}
			}
		}()

		buf := make([]byte, 256)
		_, _ = clientA.Read(buf) // Greeting

		// Fail 1
		_, _ = clientA.Write([]byte("A01 LOGIN user wrong1\r\n"))
		_, _ = clientA.Read(buf) // NO

		// Fail 2
		_, _ = clientA.Write([]byte("A02 LOGIN user wrong2\r\n"))
		n, _ := clientA.Read(buf) // Should receive A02 NO or * BYE
		resp := string(buf[:n])
		if !strings.Contains(resp, "NO") {
			t.Errorf("expected tagged NO response, got %s", resp)
		}

		// Subsequent read should get * BYE
		n, _ = clientA.Read(buf)
		bye := string(buf[:n])
		if !strings.Contains(bye, "* BYE Too many authentication failures") {
			t.Errorf("expected BYE message, got %s", bye)
		}

		res := <-done
		if !res.blocked {
			t.Errorf("expected session to be marked blocked")
		}
	})

	t.Run("LineTooLong_ReturnsBad", func(t *testing.T) {
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
			_, _ = upB.Write([]byte("* OK Dovecot ready\r\n"))
		}()

		buf := make([]byte, 128)
		_, _ = clientA.Read(buf) // Greeting

		oversized := strings.Repeat("C", 4100)
		go func() {
			_, _ = clientA.Write([]byte(oversized))
		}()

		n, _ := clientA.Read(buf)
		if !strings.HasPrefix(string(buf[:n]), "* BAD") {
			t.Errorf("expected * BAD Line too long, got: %s", string(buf[:n]))
		}

		_ = clientA.Close()
		_ = upA.Close()
		<-done
	})
}

