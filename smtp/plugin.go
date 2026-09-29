package smtp

import (
	_ "embed"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
)

//go:embed plugin.yaml
var manifestYAML []byte

func init() {
	plugins.Register(&Plugin{})
}

// Plugin implements sdk.Plugin for SMTP protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.MustParseManifest(manifestYAML)
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	if v, exists := config["max_recipients"]; exists {
		switch v.(type) {
		case int, int64, float64:
		default:
			return fmt.Errorf("max_recipients must be an integer, got %T", v)
		}
	}
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	insp := &Inspector{}
	if config != nil {
		if v, ok := config["max_recipients"]; ok {
			switch n := v.(type) {
			case int:
				insp.MaxRecipients = n
			case int64:
				insp.MaxRecipients = int(n)
			case float64:
				insp.MaxRecipients = int(n)
			}
		}
		if domains, ok := config["blocked_sender_domains"].([]any); ok {
			for _, d := range domains {
				if s, ok := d.(string); ok {
					insp.BlockedSenderDomains = append(insp.BlockedSenderDomains, s)
				}
			}
		} else if domains, ok := config["blocked_sender_domains"].([]string); ok {
			insp.BlockedSenderDomains = domains
		}
		if v, ok := config["require_starttls"].(bool); ok {
			insp.RequireSTARTTLS = v
		}
	}
	return insp, nil
}

// SelfTest executes synthetic in-memory test validating SMTP 535 auth failure tracking.
func (p *Plugin) SelfTest() error {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	authFailureTriggered := false
	var mu sync.Mutex

	ctx := &sdk.DefaultContext{
		ServiceName:   "selftest-smtp",
		ClientAddress: "127.0.0.1",
		AuthFailureFunc: func() {
			mu.Lock()
			authFailureTriggered = true
			mu.Unlock()
		},
	}

	insp := &Inspector{}
	done := make(chan error, 1)

	go func() {
		_, _, _, err := insp.Run(ctx, clientB, upA)
		done <- err
	}()

	// Synthetic upstream server
	go func() {
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte("220 mail.example.com ESMTP Postfix\r\n"))

		var buf [256]byte
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Read(buf[:]) // EHLO

		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte("250-mail.example.com\r\n250 AUTH PLAIN LOGIN\r\n"))

		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Read(buf[:]) // AUTH PLAIN

		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte("535 5.7.8 Authentication credentials invalid\r\n"))
	}()

	// Synthetic client
	go func() {
		var buf [256]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(buf[:]) // 220

		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write([]byte("EHLO client.example.com\r\n"))

		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(buf[:]) // 250

		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write([]byte("AUTH PLAIN dGVzdAB0ZXN0AHRlc3Q=\r\n"))

		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(buf[:]) // 535
	}()

	select {
	case <-time.After(500 * time.Millisecond):
		mu.Lock()
		triggered := authFailureTriggered
		mu.Unlock()
		if !triggered {
			return errors.New("self-test failed: SMTP 535 did not trigger OnAuthFailure")
		}
		return nil
	case err := <-done:
		if err != nil {
			return fmt.Errorf("self-test returned error: %w", err)
		}
		mu.Lock()
		triggered := authFailureTriggered
		mu.Unlock()
		if !triggered {
			return errors.New("self-test failed: SMTP 535 did not trigger OnAuthFailure")
		}
		return nil
	}
}
