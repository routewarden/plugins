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
