package vnc

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func TestVNC_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest() failed: %v", err)
	}
}

func TestVNC_ValidateConfig(t *testing.T) {
	p := &Plugin{}

	valid := map[string]any{
		"blocked_security_types": []any{1}, // block None
	}
	if err := p.ValidateConfig(valid); err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}

	invalid := map[string]any{
		"blocked_security_types": "bad",
	}
	if err := p.ValidateConfig(invalid); err == nil {
		t.Fatal("expected error for invalid config, got nil")
	}
}

func TestVNC_BlockedSecurityType(t *testing.T) {
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
		BlockedSecurityTypes: []int{secTypeNone}, // block no-auth
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

	// Server mock: send RFB version, then security types offering None (1) and VncAuth (2)
	go func() {
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte("RFB 003.008\n"))

		var cVer [12]byte
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.ReadFull(upB, cVer[:])

		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte{2, secTypeNone, secTypeVncAuth})
	}()

	// Client: read version, send version, read sec types, choose None (1) which is blocked
	var sVer [12]byte
	_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadFull(clientA, sVer[:])

	_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = clientA.Write([]byte("RFB 003.008\n"))

	var secTypes [3]byte
	_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadFull(clientA, secTypes[:])

	// Send chosen secTypeNone (1)
	_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = clientA.Write([]byte{secTypeNone})

	// Read failed result from inspector
	var failBuf [64]byte
	_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := clientA.Read(failBuf[:])
	_ = clientA.Close()

	if n >= 4 {
		code := binary.BigEndian.Uint32(failBuf[0:4])
		if code != secResultFailed {
			t.Errorf("expected secResultFailed (1), got %d", code)
		}
	}

	select {
	case res := <-done:
		if !res.blocked {
			t.Errorf("expected blocked=true, got %v", res.blocked)
		}
		if securityAction != "blocked" {
			t.Errorf("expected securityAction 'blocked', got %q", securityAction)
		}
		if !strings.Contains(securityReason, "1") {
			t.Errorf("expected securityReason to mention type 1, got %q", securityReason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test timed out")
	}
}

func TestVNC_InvalidServerBanner(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{}
	ctx := &sdk.DefaultContext{}

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

	// Server sends non-RFB banner (12 bytes)
	go func() {
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte("HTTP/1.1 200"))
	}()

	select {
	case res := <-done:
		if !res.blocked {
			t.Errorf("expected blocked=true for invalid RFB banner, got %v", res.blocked)
		}
		if !strings.Contains(res.reason, "not a valid RFB/VNC handshake") {
			t.Errorf("unexpected block reason: %q", res.reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for inspector to reject invalid banner")
	}
}

func TestVNC_NoneAuthAllowedAndProxy(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{
		BlockedSecurityTypes: []int{}, // none is allowed
	}
	ctx := &sdk.DefaultContext{}

	done := make(chan struct {
		res     sdk.ProxyResult
		blocked bool
	}, 1)

	go func() {
		res, blocked, _, _ := insp.Run(ctx, clientB, upA)
		done <- struct {
			res     sdk.ProxyResult
			blocked bool
		}{res, blocked}
	}()

	// Upstream mock: RFB 3.8, offers secTypeNone (1), sends secResultOK
	go func() {
		_ = upB.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = upB.Write([]byte("RFB 003.008\n"))

		var cVer [12]byte
		_, _ = io.ReadFull(upB, cVer[:])

		_, _ = upB.Write([]byte{1, secTypeNone})

		var chosen [1]byte
		_, _ = io.ReadFull(upB, chosen[:])

		var okBuf [4]byte
		binary.BigEndian.PutUint32(okBuf[:], secResultOK)
		_, _ = upB.Write(okBuf[:])

		// Wait for post-handshake client message and respond
		buf := make([]byte, 4)
		_, _ = io.ReadFull(upB, buf)
		if string(buf) == "PING" {
			_, _ = upB.Write([]byte("PONG"))
		}
		_ = upB.Close()
	}()

	// Client mock
	go func() {
		_ = clientA.SetDeadline(time.Now().Add(3 * time.Second))
		var sVer [12]byte
		_, _ = io.ReadFull(clientA, sVer[:])

		_, _ = clientA.Write([]byte("RFB 003.008\n"))

		var secTypes [2]byte
		_, _ = io.ReadFull(clientA, secTypes[:])

		_, _ = clientA.Write([]byte{secTypeNone})

		var resBuf [4]byte
		_, _ = io.ReadFull(clientA, resBuf[:])

		// Handshake complete, send proxy ping
		_, _ = clientA.Write([]byte("PING"))
		resp := make([]byte, 4)
		_, _ = io.ReadFull(clientA, resp)
		_ = clientA.Close()
	}()

	select {
	case outcome := <-done:
		if outcome.blocked {
			t.Errorf("expected connection to be allowed, got blocked=true")
		}
		if outcome.res.BytesIn == 0 || outcome.res.BytesOut == 0 {
			t.Errorf("expected nonzero bytes transferred, got in=%d out=%d", outcome.res.BytesIn, outcome.res.BytesOut)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test timed out")
	}
}

func TestVNC_AuthSuccessAndProxy(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{}
	ctx := &sdk.DefaultContext{}

	done := make(chan struct {
		res     sdk.ProxyResult
		blocked bool
	}, 1)

	go func() {
		res, blocked, _, _ := insp.Run(ctx, clientB, upA)
		done <- struct {
			res     sdk.ProxyResult
			blocked bool
		}{res, blocked}
	}()

	// Upstream mock: VncAuth challenge/response
	go func() {
		_ = upB.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = upB.Write([]byte("RFB 003.008\n"))

		var cVer [12]byte
		_, _ = io.ReadFull(upB, cVer[:])

		_, _ = upB.Write([]byte{1, secTypeVncAuth})

		var chosen [1]byte
		_, _ = io.ReadFull(upB, chosen[:])

		// Send 16-byte challenge
		var challenge [16]byte
		copy(challenge[:], "0123456789abcdef")
		_, _ = upB.Write(challenge[:])

		// Read 16-byte response
		var clientResp [16]byte
		_, _ = io.ReadFull(upB, clientResp[:])

		// Send SecurityResult OK
		var okBuf [4]byte
		binary.BigEndian.PutUint32(okBuf[:], secResultOK)
		_, _ = upB.Write(okBuf[:])

		// Post-handshake communication
		buf := make([]byte, 4)
		_, _ = io.ReadFull(upB, buf)
		if string(buf) == "ECHO" {
			_, _ = upB.Write([]byte("HELO"))
		}
		_ = upB.Close()
	}()

	// Client mock
	go func() {
		_ = clientA.SetDeadline(time.Now().Add(3 * time.Second))
		var sVer [12]byte
		_, _ = io.ReadFull(clientA, sVer[:])

		_, _ = clientA.Write([]byte("RFB 003.008\n"))

		var secTypes [2]byte
		_, _ = io.ReadFull(clientA, secTypes[:])

		_, _ = clientA.Write([]byte{secTypeVncAuth})

		var chal [16]byte
		_, _ = io.ReadFull(clientA, chal[:])

		var resp [16]byte
		copy(resp[:], "fedcba9876543210")
		_, _ = clientA.Write(resp[:])

		var resBuf [4]byte
		_, _ = io.ReadFull(clientA, resBuf[:])

		_, _ = clientA.Write([]byte("ECHO"))
		ret := make([]byte, 4)
		_, _ = io.ReadFull(clientA, ret)
		_ = clientA.Close()
	}()

	select {
	case outcome := <-done:
		if outcome.blocked {
			t.Errorf("expected connection to be allowed, got blocked=true")
		}
		if outcome.res.BytesIn == 0 || outcome.res.BytesOut == 0 {
			t.Errorf("expected nonzero bytes transferred, got in=%d out=%d", outcome.res.BytesIn, outcome.res.BytesOut)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test timed out")
	}
}

