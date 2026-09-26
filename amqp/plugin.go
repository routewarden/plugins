package amqp

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

// AMQP 0-9-1 frame types
const (
	frameMethod    = 1
	frameBody      = 3
	frameHeartbeat = 8
	frameEnd       = 0xCE

	// AMQP class/method IDs
	classConnection = 10
	methodStart     = 10
	methodStartOk   = 11
	methodTune      = 30
	methodTuneOk    = 31
	methodOpen      = 40
	methodOpenOk    = 41
	methodClose     = 50
	methodCloseOk   = 51

	// AMQP reply codes indicating auth failure
	replyAccessRefused   = 403
	replyNotAllowed      = 530
	replyNotAllowedAlt   = 541
)

// Plugin implements sdk.Plugin for AMQP 0-9-1 (RabbitMQ) protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "amqp",
		Version:     "1.0.0",
		Description: "AMQP 0-9-1 (RabbitMQ) protocol inspector with auth failure detection and vhost filtering",
		Author:      "RouteWarden Team",
		Protocols:   []string{"amqp", "rabbitmq"},
	}
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	if v, exists := config["max_auth_failures"]; exists {
		switch v.(type) {
		case int, int64, float64:
		default:
			return fmt.Errorf("max_auth_failures must be an integer, got %T", v)
		}
	}
	if v, exists := config["allowed_vhosts"]; exists {
		switch items := v.(type) {
		case []string:
		case []any:
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("allowed_vhosts must contain strings, got %T", item)
				}
			}
		default:
			return fmt.Errorf("allowed_vhosts must be a list of strings, got %T", items)
		}
	}
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	insp := &Inspector{}
	if config == nil {
		return insp, nil
	}
	if v, ok := config["max_auth_failures"]; ok {
		switch n := v.(type) {
		case int:
			insp.MaxAuthFailures = n
		case int64:
			insp.MaxAuthFailures = int(n)
		case float64:
			insp.MaxAuthFailures = int(n)
		}
	}
	if v, ok := config["allowed_vhosts"]; ok {
		switch items := v.(type) {
		case []string:
			insp.AllowedVHosts = items
		case []any:
			for _, item := range items {
				if s, ok := item.(string); ok {
					insp.AllowedVHosts = append(insp.AllowedVHosts, s)
				}
			}
		}
	}
	return insp, nil
}

// SelfTest verifies that an AMQP Connection.Close with reply code 530 triggers OnAuthFailure.
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
		ServiceName:   "selftest-amqp",
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

	// Synthetic client: send AMQP protocol header
	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write([]byte("AMQP\x00\x00\x09\x01"))

		// Read server Connection.Start
		var buf [512]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(buf[:])

		// Send Connection.Start-Ok (simple auth)
		startOk := buildConnectionStartOk("guest", "guest")
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write(startOk)

		// Read any response (Connection.Close with auth failure)
		var resp [256]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(resp[:])
	}()

	// Synthetic server: read header, send Connection.Start, read Start-Ok, send Connection.Close (530)
	go func() {
		var header [8]byte
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(upB, header[:]); err != nil {
			return
		}

		// Send Connection.Start frame
		start := buildConnectionStart()
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write(start)

		// Read Connection.Start-Ok
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := readAMQPFrame(upB); err != nil {
			return
		}

		// Send Connection.Close with reply code 530 (Not Allowed — auth failure)
		closeFrame := buildConnectionClose(replyNotAllowed, "ACCESS_REFUSED - Login was refused")
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write(closeFrame)
	}()

	select {
	case <-done:
		mu.Lock()
		triggered := authFailureTriggered
		mu.Unlock()
		if !triggered {
			return errors.New("self-test failed: AMQP Connection.Close 530 did not trigger OnAuthFailure")
		}
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("self-test timed out after 3s")
	}
}

// Inspector inspects the AMQP 0-9-1 handshake for auth failures and vhost violations.
type Inspector struct {
	MaxAuthFailures int
	AllowedVHosts   []string
}

// Run inspects the AMQP handshake, then switches to raw proxy mode after Connection.Open-Ok.
func (insp *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	var bytesIn, bytesOut atomic.Int64

	result := func(err error) sdk.ProxyResult {
		return sdk.ProxyResult{BytesIn: bytesIn.Load(), BytesOut: bytesOut.Load(), Err: err}
	}

	// 1. Read and forward AMQP protocol header (8 bytes: "AMQP\x00\x00\x09\x01")
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	var protoHeader [8]byte
	if _, err := io.ReadFull(client, protoHeader[:]); err != nil {
		return result(err), true, "failed reading AMQP protocol header", err
	}
	if string(protoHeader[0:4]) != "AMQP" {
		return result(nil), true, "not an AMQP connection (invalid protocol header)", nil
	}
	bytesIn.Add(8)

	upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := upstream.Write(protoHeader[:]); err != nil {
		return result(err), true, "failed forwarding AMQP protocol header", err
	}
	bytesOut.Add(8)

	// 2. Inspect handshake frames until Connection.Open-Ok or Connection.Close
	for {
		// Try reading from upstream first (server-initiated frames)
		upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
		frame, err := readAMQPFrame(upstream)
		if err != nil {
			return result(err), false, "", nil
		}
		bytesOut.Add(int64(len(frame.raw)))

		class, method := extractClassMethod(frame)

		// Inspect server-sent Connection.Close for auth failure codes
		if frame.frameType == frameMethod && class == classConnection && method == methodClose {
			replyCode := extractCloseReplyCode(frame.payload)
			if replyCode == replyAccessRefused || replyCode == replyNotAllowed || replyCode == replyNotAllowedAlt {
				if ctx != nil {
					ctx.OnAuthFailure()
					ctx.OnSecurityEvent("auth_failure", fmt.Sprintf("amqp_auth_failed_code_%d", replyCode))
				}
			}
			// Forward to client and return
			client.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, _ = client.Write(frame.raw)
			return result(nil), false, "", nil
		}

		// Forward server frame to client
		client.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := client.Write(frame.raw); err != nil {
			return result(err), false, "", nil
		}

		// After Connection.Open-Ok, switch to raw proxy
		if frame.frameType == frameMethod && class == classConnection && method == methodOpenOk {
			client.SetDeadline(time.Time{})
			upstream.SetDeadline(time.Time{})
			res := protocol.Proxy(client, upstream)
			bytesIn.Add(res.BytesIn)
			bytesOut.Add(res.BytesOut)
			return result(nil), false, "", nil
		}

		// Read client response frame
		client.SetReadDeadline(time.Now().Add(30 * time.Second))
		clientFrame, err := readAMQPFrame(client)
		if err != nil {
			return result(err), false, "", nil
		}
		bytesIn.Add(int64(len(clientFrame.raw)))

		clientClass, clientMethod := extractClassMethod(clientFrame)

		// Check vhost on Connection.Open
		if clientFrame.frameType == frameMethod && clientClass == classConnection && clientMethod == methodOpen {
			if len(insp.AllowedVHosts) > 0 {
				vhost := extractVHost(clientFrame.payload)
				if !isVHostAllowed(vhost, insp.AllowedVHosts) {
					if ctx != nil {
						ctx.OnSecurityEvent("blocked", "amqp_vhost_not_allowed_"+vhost)
					}
					// Send Connection.Close to client
					closeFrame := buildConnectionClose(replyNotAllowed, "NOT_ALLOWED - vhost '"+vhost+"' denied by RouteWarden")
					client.SetWriteDeadline(time.Now().Add(5 * time.Second))
					_, _ = client.Write(closeFrame)
					return result(nil), true, "amqp vhost not allowed: " + vhost, nil
				}
			}
		}

		// Forward client frame to upstream
		upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := upstream.Write(clientFrame.raw); err != nil {
			return result(err), false, "", nil
		}

		// In AMQP 0-9-1, after sending Connection.Tune-Ok, the client immediately sends Connection.Open
		// without waiting for any server response. Read and process it immediately.
		if clientFrame.frameType == frameMethod && clientClass == classConnection && clientMethod == methodTuneOk {
			client.SetReadDeadline(time.Now().Add(30 * time.Second))
			openFrame, err := readAMQPFrame(client)
			if err != nil {
				return result(err), false, "", nil
			}
			bytesIn.Add(int64(len(openFrame.raw)))

			oClass, oMethod := extractClassMethod(openFrame)
			if openFrame.frameType == frameMethod && oClass == classConnection && oMethod == methodOpen {
				if len(insp.AllowedVHosts) > 0 {
					vhost := extractVHost(openFrame.payload)
					if !isVHostAllowed(vhost, insp.AllowedVHosts) {
						if ctx != nil {
							ctx.OnSecurityEvent("blocked", "amqp_vhost_not_allowed_"+vhost)
						}
						closeFrame := buildConnectionClose(replyNotAllowed, "NOT_ALLOWED - vhost '"+vhost+"' denied by RouteWarden")
						client.SetWriteDeadline(time.Now().Add(5 * time.Second))
						_, _ = client.Write(closeFrame)
						return result(nil), true, "amqp vhost not allowed: " + vhost, nil
					}
				}
			}

			upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := upstream.Write(openFrame.raw); err != nil {
				return result(err), false, "", nil
			}
		}
	}
}

type amqpFrame struct {
	frameType byte
	channel   uint16
	payload   []byte
	raw       []byte
}

func readAMQPFrame(conn net.Conn) (*amqpFrame, error) {
	// Frame header: type(1) + channel(2) + size(4) = 7 bytes
	var header [7]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	frameType := header[0]
	channel := binary.BigEndian.Uint16(header[1:3])
	size := binary.BigEndian.Uint32(header[3:7])

	if size > 128*1024 { // 128KB max frame
		return nil, fmt.Errorf("AMQP frame too large: %d", size)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	// Frame-end byte
	var end [1]byte
	if _, err := io.ReadFull(conn, end[:]); err != nil {
		return nil, err
	}
	if end[0] != frameEnd {
		return nil, fmt.Errorf("invalid AMQP frame-end byte: 0x%02x", end[0])
	}

	raw := make([]byte, 7+len(payload)+1)
	copy(raw, header[:])
	copy(raw[7:], payload)
	raw[7+len(payload)] = frameEnd

	return &amqpFrame{
		frameType: frameType,
		channel:   channel,
		payload:   payload,
		raw:       raw,
	}, nil
}

func extractClassMethod(f *amqpFrame) (uint16, uint16) {
	if f.frameType != frameMethod || len(f.payload) < 4 {
		return 0, 0
	}
	class := binary.BigEndian.Uint16(f.payload[0:2])
	method := binary.BigEndian.Uint16(f.payload[2:4])
	return class, method
}

func extractCloseReplyCode(payload []byte) int {
	if len(payload) < 6 {
		return 0
	}
	return int(binary.BigEndian.Uint16(payload[4:6]))
}

func extractVHost(payload []byte) string {
	// Connection.Open payload: class(2) + method(2) + vhost (short string)
	if len(payload) < 5 {
		return "/"
	}
	vhostLen := int(payload[4])
	if 5+vhostLen > len(payload) {
		return "/"
	}
	return string(payload[5 : 5+vhostLen])
}

func isVHostAllowed(vhost string, allowed []string) bool {
	for _, v := range allowed {
		if strings.EqualFold(vhost, v) {
			return true
		}
	}
	return false
}

// buildConnectionStart builds a minimal AMQP Connection.Start frame.
func buildConnectionStart() []byte {
	// Connection.Start payload: class=10, method=10, version-major=0, version-minor=9,
	// server-properties (empty table), mechanisms="PLAIN", locales="en_US"
	payload := []byte{
		0x00, 0x0A, // class 10
		0x00, 0x0A, // method 10
		0x00, 0x09, // version major/minor
		0x00, 0x00, 0x00, 0x00, // empty server-properties table
		0x00, 0x00, 0x00, 0x05, 'P', 'L', 'A', 'I', 'N', // mechanism "PLAIN"
		0x00, 0x00, 0x00, 0x05, 'e', 'n', '_', 'U', 'S', // locale "en_US"
	}
	return buildAMQPFrame(frameMethod, 0, payload)
}

// buildConnectionStartOk builds a Connection.Start-Ok frame with PLAIN credentials.
func buildConnectionStartOk(user, pass string) []byte {
	// PLAIN: \x00username\x00password
	sasl := "\x00" + user + "\x00" + pass
	payload := []byte{
		0x00, 0x0A, // class 10
		0x00, 0x0B, // method 11 (Start-Ok)
		0x00, 0x00, 0x00, 0x00, // empty client-properties
		0x00, 0x00, 0x00, 0x05, 'P', 'L', 'A', 'I', 'N', // mechanism
	}
	// response (long string)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(sasl)))
	payload = append(payload, lenBuf[:]...)
	payload = append(payload, []byte(sasl)...)
	payload = append(payload, 0x00, 0x00, 0x00, 0x05, 'e', 'n', '_', 'U', 'S') // locale
	return buildAMQPFrame(frameMethod, 0, payload)
}

// buildConnectionClose builds a Connection.Close frame.
func buildConnectionClose(replyCode int, replyText string) []byte {
	payload := []byte{
		0x00, 0x0A, // class 10
		0x00, 0x32, // method 50 (Close)
	}
	var codeBuf [2]byte
	binary.BigEndian.PutUint16(codeBuf[:], uint16(replyCode))
	payload = append(payload, codeBuf[:]...)
	payload = append(payload, byte(len(replyText)))
	payload = append(payload, []byte(replyText)...)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00) // failing-class-id, failing-method-id
	return buildAMQPFrame(frameMethod, 0, payload)
}

func buildAMQPFrame(frameType byte, channel uint16, payload []byte) []byte {
	frame := make([]byte, 7+len(payload)+1)
	frame[0] = frameType
	binary.BigEndian.PutUint16(frame[1:3], channel)
	binary.BigEndian.PutUint32(frame[3:7], uint32(len(payload)))
	copy(frame[7:], payload)
	frame[7+len(payload)] = frameEnd
	return frame
}
