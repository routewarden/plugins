package vnc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

func init() {
	plugins.Register(&Plugin{})
}

// RFB Security Types
const (
	secTypeInvalid  = 0
	secTypeNone     = 1
	secTypeVncAuth  = 2
	secTypeRA2      = 5
	secTypeRA2ne    = 6
	secTypeTight    = 16
	secTypeUltra    = 17
	secTypeTLS      = 18
	secTypeVeNCrypt = 19

	// RFB Security Result Codes
	secResultOK     = 0
	secResultFailed = 1
)

// Plugin implements sdk.Plugin for VNC / RFB protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "vnc",
		Version:     "1.0.0",
		Description: "VNC/RFB protocol inspector with auth failure detection and version filtering",
		Author:      "RouteWarden Team",
		Protocols:   []string{"vnc", "rfb"},
	}
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	if v, exists := config["blocked_security_types"]; exists {
		switch items := v.(type) {
		case []int:
		case []any:
			for _, item := range items {
				switch item.(type) {
				case int, int64, float64:
				default:
					return fmt.Errorf("blocked_security_types must be a list of integers")
				}
			}
		default:
			return fmt.Errorf("blocked_security_types must be a list of integers, got %T", v)
		}
	}
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	insp := &Inspector{}
	if config == nil {
		return insp, nil
	}
	if v, ok := config["blocked_security_types"]; ok {
		switch items := v.(type) {
		case []int:
			insp.BlockedSecurityTypes = items
		case []any:
			for _, item := range items {
				switch n := item.(type) {
				case int:
					insp.BlockedSecurityTypes = append(insp.BlockedSecurityTypes, n)
				case int64:
					insp.BlockedSecurityTypes = append(insp.BlockedSecurityTypes, int(n))
				case float64:
					insp.BlockedSecurityTypes = append(insp.BlockedSecurityTypes, int(n))
				}
			}
		}
	}
	return insp, nil
}

// SelfTest verifies that an RFB SecurityResult of Failed (1) triggers OnAuthFailure.
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
		ServiceName:   "selftest-vnc",
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

	// Upstream server mock:
	go func() {
		// 1. Send server version "RFB 003.008\n"
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte("RFB 003.008\n"))

		// Read client version
		var clientVer [12]byte
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(upB, clientVer[:]); err != nil {
			return
		}

		// 2. Send security types: 1 type (VncAuth = 2)
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write([]byte{1, secTypeVncAuth})

		// Read client chosen security type
		var chosen [1]byte
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(upB, chosen[:]); err != nil {
			return
		}

		// 3. Send 16-byte challenge
		var challenge [16]byte
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write(challenge[:])

		// Read 16-byte client response
		var clientResp [16]byte
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(upB, clientResp[:]); err != nil {
			return
		}

		// 4. Send SecurityResult Failed (1) + error message
		var resultBuf [8]byte
		binary.BigEndian.PutUint32(resultBuf[0:4], secResultFailed)
		binary.BigEndian.PutUint32(resultBuf[4:8], 11) // error len
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write(append(resultBuf[:], []byte("Auth failed")...))
	}()

	// Client mock:
	go func() {
		// Read server version
		var sVer [12]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(clientA, sVer[:]); err != nil {
			return
		}

		// Send client version
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write([]byte("RFB 003.008\n"))

		// Read security types
		var secTypes [2]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(clientA, secTypes[:]); err != nil {
			return
		}

		// Choose VncAuth (2)
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write([]byte{secTypeVncAuth})

		// Read 16-byte challenge
		var chal [16]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(clientA, chal[:]); err != nil {
			return
		}

		// Send 16-byte response
		var chalResp [16]byte
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write(chalResp[:])

		// Read security result
		var resBuf [512]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(resBuf[:])
		_ = clientA.Close()
	}()

	select {
	case <-done:
		mu.Lock()
		triggered := authFailureTriggered
		mu.Unlock()
		if !triggered {
			return errors.New("self-test failed: VNC auth failure did not trigger OnAuthFailure")
		}
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("self-test timed out after 3s")
	}
}

// Inspector monitors VNC / RFB protocol handshakes for authentication events.
type Inspector struct {
	BlockedSecurityTypes []int
}

// Run executes the RFB handshake inspector and then delegates to raw proxying.
func (insp *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	var bytesIn, bytesOut atomic.Int64

	result := func(err error) sdk.ProxyResult {
		return sdk.ProxyResult{BytesIn: bytesIn.Load(), BytesOut: bytesOut.Load(), Err: err}
	}

	// 1. Server sends 12-byte ProtocolVersion: "RFB 003.008\n"
	upstream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var serverVer [12]byte
	if _, err := io.ReadFull(upstream, serverVer[:]); err != nil {
		return result(err), false, "", nil
	}
	bytesOut.Add(12)

	if !strings.HasPrefix(string(serverVer[:]), "RFB ") {
		return result(nil), true, "not a valid RFB/VNC handshake", nil
	}

	// Forward server version to client
	client.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := client.Write(serverVer[:]); err != nil {
		return result(err), false, "", nil
	}

	// 2. Client responds with 12-byte ProtocolVersion
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	var clientVer [12]byte
	if _, err := io.ReadFull(client, clientVer[:]); err != nil {
		return result(err), false, "", nil
	}
	bytesIn.Add(12)

	// Forward client version to upstream
	upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := upstream.Write(clientVer[:]); err != nil {
		return result(err), false, "", nil
	}

	// 3. Server sends security types (RFB 3.7+ format)
	upstream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var numSecBuf [1]byte
	if _, err := io.ReadFull(upstream, numSecBuf[:]); err != nil {
		return result(err), false, "", nil
	}
	bytesOut.Add(1)
	numSec := int(numSecBuf[0])

	if numSec == 0 {
		// Server rejected connection before security handshake (RFB 3.7+ error reason follows)
		var errLenBuf [4]byte
		if _, err := io.ReadFull(upstream, errLenBuf[:]); err == nil {
			bytesOut.Add(4)
			errLen := binary.BigEndian.Uint32(errLenBuf[:])
			if errLen > 0 && errLen < 4096 {
				errStr := make([]byte, errLen)
				if _, err := io.ReadFull(upstream, errStr); err == nil {
					bytesOut.Add(int64(errLen))
					client.SetWriteDeadline(time.Now().Add(5 * time.Second))
					_, _ = client.Write(append(append(numSecBuf[:], errLenBuf[:]...), errStr...))
					return result(nil), false, "", nil
				}
			}
		}
		client.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = client.Write(numSecBuf[:])
		return result(nil), false, "", nil
	}

	secTypes := make([]byte, numSec)
	if _, err := io.ReadFull(upstream, secTypes); err != nil {
		return result(err), false, "", nil
	}
	bytesOut.Add(int64(numSec))

	// Forward security types to client
	client.SetWriteDeadline(time.Now().Add(10 * time.Second))
	fullSec := append(numSecBuf[:], secTypes...)
	if _, err := client.Write(fullSec); err != nil {
		return result(err), false, "", nil
	}

	// 4. Client selects security type (1 byte)
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	var chosenSecBuf [1]byte
	if _, err := io.ReadFull(client, chosenSecBuf[:]); err != nil {
		return result(err), false, "", nil
	}
	bytesIn.Add(1)
	chosenSec := int(chosenSecBuf[0])

	// Check if this security type is blocked
	for _, blocked := range insp.BlockedSecurityTypes {
		if blocked == chosenSec {
			if ctx != nil {
				ctx.OnSecurityEvent("blocked", fmt.Sprintf("vnc_security_type_%d_blocked", chosenSec))
			}
			// Send SecurityResult failed
			var failResult [8]byte
			binary.BigEndian.PutUint32(failResult[0:4], secResultFailed)
			errMsg := "Security type blocked by RouteWarden"
			binary.BigEndian.PutUint32(failResult[4:8], uint32(len(errMsg)))
			client.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = client.Write(append(failResult[:], []byte(errMsg)...))
			return result(nil), true, fmt.Sprintf("blocked vnc security type %d", chosenSec), nil
		}
	}

	// Forward choice to upstream
	upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := upstream.Write(chosenSecBuf[:]); err != nil {
		return result(err), false, "", nil
	}

	// 5. If VncAuth (2), inspect challenge-response
	if chosenSec == secTypeVncAuth {
		// Server sends 16-byte challenge
		upstream.SetReadDeadline(time.Now().Add(10 * time.Second))
		var challenge [16]byte
		if _, err := io.ReadFull(upstream, challenge[:]); err != nil {
			return result(err), false, "", nil
		}
		bytesOut.Add(16)

		// Forward challenge to client
		client.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := client.Write(challenge[:]); err != nil {
			return result(err), false, "", nil
		}

		// Client responds with 16-byte response
		client.SetReadDeadline(time.Now().Add(30 * time.Second))
		var clientResponse [16]byte
		if _, err := io.ReadFull(client, clientResponse[:]); err != nil {
			return result(err), false, "", nil
		}
		bytesIn.Add(16)

		// Forward response to upstream
		upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := upstream.Write(clientResponse[:]); err != nil {
			return result(err), false, "", nil
		}
	}

	// 6. Server sends SecurityResult (4 bytes)
	upstream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var secResultBuf [4]byte
	if _, err := io.ReadFull(upstream, secResultBuf[:]); err != nil {
		return result(err), false, "", nil
	}
	bytesOut.Add(4)
	secResult := binary.BigEndian.Uint32(secResultBuf[:])

	if secResult == secResultFailed {
		if ctx != nil {
			ctx.OnAuthFailure()
			ctx.OnSecurityEvent("auth_failure", "vnc_auth_failed")
		}
		// Read optional reason length and reason string
		var lenBuf [4]byte
		if _, err := io.ReadFull(upstream, lenBuf[:]); err == nil {
			bytesOut.Add(4)
			reasonLen := binary.BigEndian.Uint32(lenBuf[:])
			if reasonLen > 0 && reasonLen < 1024 {
				reasonStr := make([]byte, reasonLen)
				if _, err := io.ReadFull(upstream, reasonStr); err == nil {
					bytesOut.Add(int64(reasonLen))
					client.SetWriteDeadline(time.Now().Add(5 * time.Second))
					_, _ = client.Write(append(append(secResultBuf[:], lenBuf[:]...), reasonStr...))
					return result(nil), false, "", nil
				}
			}
		}
		client.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = client.Write(secResultBuf[:])
		return result(nil), false, "", nil
	}

	// Forward successful SecurityResult to client
	client.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := client.Write(secResultBuf[:]); err != nil {
		return result(err), false, "", nil
	}

	// 7. Handshake complete! Switch to raw bidirectional proxy
	client.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})
	proxyRes := protocol.Proxy(client, upstream)
	bytesIn.Add(proxyRes.BytesIn)
	bytesOut.Add(proxyRes.BytesOut)
	return result(nil), false, "", nil
}
