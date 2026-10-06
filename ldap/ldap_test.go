package ldap

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func TestLDAP_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest() failed: %v", err)
	}
}

func TestLDAP_ValidateConfig(t *testing.T) {
	p := &Plugin{}

	valid := map[string]any{
		"blocked_dns":      []any{"cn=admin,dc=example,dc=com", "ou=secrets,dc=example,dc=com"},
		"allowed_base_dns": []any{"dc=example,dc=com"},
	}
	if err := p.ValidateConfig(valid); err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}

	invalid := map[string]any{
		"blocked_dns": 42,
	}
	if err := p.ValidateConfig(invalid); err == nil {
		t.Fatal("expected error for invalid blocked_dns type, got nil")
	}
}

func TestLDAP_BlockedDN(t *testing.T) {
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
		BlockedDNs: []string{"cn=root,dc=company,dc=org"},
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

	// Client sends BindRequest with blocked DN
	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		bind := buildBindRequest(42, "cn=root,dc=company,dc=org", "supersecret")
		_, _ = clientA.Write(bind)

		// Read response
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = readBERMessage(clientA)
		_ = clientA.Close()
	}()

	select {
	case res := <-done:
		if !res.blocked {
			t.Errorf("expected blocked=true, got %v", res.blocked)
		}
		if securityAction != "blocked" {
			t.Errorf("expected securityAction 'blocked', got %q", securityAction)
		}
		if !strings.Contains(securityReason, "cn=root,dc=company,dc=org") {
			t.Errorf("expected securityReason to contain blocked DN, got %q", securityReason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test timed out")
	}
}

func TestLDAP_SecurityBoundaries(t *testing.T) {
	t.Run("BaseDN_SuffixSpoofingPrevented", func(t *testing.T) {
		insp := &Inspector{
			AllowedBaseDNs: []string{"dc=corp,dc=local"},
		}

		// Exact match should be allowed (not blocked)
		if insp.isDNBlocked("dc=corp,dc=local") {
			t.Errorf("expected base DN itself to be allowed")
		}

		// Sub-DN should be allowed
		if insp.isDNBlocked("cn=alice,ou=users,dc=corp,dc=local") {
			t.Errorf("expected sub-DN under corp.local to be allowed")
		}

		// Suffix spoofing (evilcorp.local vs corp.local) MUST be blocked
		if !insp.isDNBlocked("cn=mallory,ou=users,dc=evilcorp,dc=local") {
			t.Errorf("expected evilcorp.local to be blocked as outside base DN")
		}
	})

	t.Run("BlockedDN_WhitespaceEvasionPrevented", func(t *testing.T) {
		insp := &Inspector{
			BlockedDNs: []string{"cn=root,dc=company,dc=org"},
		}

		// Spaces after commas should still be detected as blocked
		if !insp.isDNBlocked("cn=root, dc=company, dc=org") {
			t.Errorf("expected spaced DN to match blocked DN")
		}

		if !insp.isDNBlocked("cn=root ,dc=company , dc=org") {
			t.Errorf("expected spaced DN to match blocked DN")
		}
	})

	t.Run("BER_IndefiniteLengthRejected", func(t *testing.T) {
		// 0x80 is BER indefinite length (numBytes == 0)
		data := []byte{0x80, 0x01, 0x02}
		lenVal, read := decodeBERLength(data)
		if read != 0 || lenVal != 0 {
			t.Errorf("expected indefinite length 0x80 to be rejected, got len=%d read=%d", lenVal, read)
		}
	})
}

