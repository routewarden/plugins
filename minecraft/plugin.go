package minecraft

import (
	_ "embed"
	"errors"
	"net"
	"time"

	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
)

//go:embed plugin.yaml
var manifestYAML []byte

func init() {
	plugins.Register(&Plugin{})
}

// Plugin implements sdk.Plugin for Minecraft protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.MustParseManifest(manifestYAML)
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	if v, ok := config["blocked_protocol_versions"]; ok {
		switch items := v.(type) {
		case []int:
		case []any:
			for _, item := range items {
				switch item.(type) {
				case int, int64, float64:
				default:
					return errors.New("blocked_protocol_versions must be a list of integers")
				}
			}
		default:
			return errors.New("blocked_protocol_versions must be a list of integers")
		}
	}
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	insp := &Inspector{}
	if config == nil {
		return insp, nil
	}
	if v, ok := config["blocked_protocol_versions"]; ok {
		switch items := v.(type) {
		case []int:
			insp.BlockedProtocolVersions = items
		case []any:
			for _, item := range items {
				switch n := item.(type) {
				case int:
					insp.BlockedProtocolVersions = append(insp.BlockedProtocolVersions, n)
				case int64:
					insp.BlockedProtocolVersions = append(insp.BlockedProtocolVersions, int(n))
				case float64:
					insp.BlockedProtocolVersions = append(insp.BlockedProtocolVersions, int(n))
				}
			}
		}
	}
	return insp, nil
}

// SelfTest executes synthetic in-memory test using net.Pipe.
func (p *Plugin) SelfTest() error {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{}
	ctx := &sdk.DefaultContext{
		ServiceName:   "selftest-minecraft",
		ClientAddress: "127.0.0.1",
	}

	done := make(chan error, 1)

	go func() {
		_, _, _, err := insp.Run(ctx, clientB, upA)
		done <- err
	}()

	// Upstream read handshake
	go func() {
		var buf [64]byte
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Read(buf[:])
		upB.Close()
	}()

	// Client sends mock handshake
	go func() {
		mockHandshake := []byte{0x0F, 0x00, 0xD2, 0x05, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x63, 0xDD, 0x01}
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write(mockHandshake)
		clientA.Close()
	}()

	select {
	case <-done:
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("self-test timed out after 3s")
	}
}
