package generic

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
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

// Plugin implements sdk.Plugin for generic TCP proxying.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.MustParseManifest(manifestYAML)
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	return &Inspector{}, nil
}

// SelfTest executes synthetic in-memory test validating bidirectional TCP proxying.
func (p *Plugin) SelfTest() error {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	ctx := &sdk.DefaultContext{
		ServiceName:   "selftest-generic",
		ClientAddress: "127.0.0.1",
	}

	insp := &Inspector{}
	done := make(chan error, 1)

	go func() {
		_, _, _, err := insp.Run(ctx, clientB, upA)
		done <- err
	}()

	testData := []byte("PING_ROUTEWARDEN_GENERIC_TCP_TEST")
	respData := []byte("PONG_ROUTEWARDEN_GENERIC_TCP_OK")

	// Client writes testData and reads respData
	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write(testData)
	}()

	// Upstream reads testData and writes respData
	receivedBuf := make([]byte, len(testData))
	_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := upB.Read(receivedBuf); err != nil {
		return fmt.Errorf("self-test upstream read failed: %w", err)
	}

	if !bytes.Equal(receivedBuf, testData) {
		return errors.New("self-test data mismatch between client and upstream")
	}

	_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = upB.Write(respData)

	clientBuf := make([]byte, len(respData))
	_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := clientA.Read(clientBuf); err != nil {
		return fmt.Errorf("self-test client read failed: %w", err)
	}

	if !bytes.Equal(clientBuf, respData) {
		return errors.New("self-test response mismatch")
	}

	return nil
}
