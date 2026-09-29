package ssh

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

// Plugin implements sdk.Plugin for SSH protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.MustParseManifest(manifestYAML)
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	if v, exists := config["max_auth_tries"]; exists {
		switch v.(type) {
		case int, int64, float64:
		default:
			return fmt.Errorf("max_auth_tries must be an integer, got %T", v)
		}
	}
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	insp := &Inspector{}
	if config != nil {
		if v, ok := config["banner"].(string); ok {
			insp.Banner = v
		}
		if v, ok := config["max_auth_tries"]; ok {
			switch n := v.(type) {
			case int:
				insp.MaxAuthTries = n
			case int64:
				insp.MaxAuthTries = int(n)
			case float64:
				insp.MaxAuthTries = int(n)
			}
		}
	}
	return insp, nil
}

// SelfTest executes synthetic in-memory test checking SSH banner parsing and auth failure tracking.
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
		ServiceName:   "selftest-ssh",
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

	// Synthetic client sends SSH-2.0 banner and consumes server responses
	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
		var buf [256]byte
		for {
			_ = clientA.SetReadDeadline(time.Now().Add(1 * time.Second))
			if _, err := clientA.Read(buf[:]); err != nil {
				return
			}
		}
	}()

	// Synthetic upstream server sends SSH banner, then SSH_MSG_USERAUTH_FAILURE (type 51)
	go func() {
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte("SSH-2.0-RouteWarden_Test\r\n"))

		// Construct synthetic SSH packet of type 51 (SSH_MSG_USERAUTH_FAILURE)
		// pktLen: 4 bytes, paddingLen: 1 byte, msgType: 51
		packet := []byte{
			0x00, 0x00, 0x00, 0x0C, // packet length = 12
			0x0A,                   // padding length = 10
			51,                     // SSH_MSG_USERAUTH_FAILURE
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
		}
		_, _ = upB.Write(packet)
	}()

	select {
	case <-time.After(500 * time.Millisecond):
		mu.Lock()
		triggered := authFailureTriggered
		mu.Unlock()
		if !triggered {
			return errors.New("self-test failed: SSH_MSG_USERAUTH_FAILURE did not trigger OnAuthFailure")
		}
		return nil
	case err := <-done:
		if err != nil {
			return fmt.Errorf("self-test returned error: %w", err)
		}
		return nil
	}
}
