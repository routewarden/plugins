package mongodb

import (
	_ "embed"
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
)

//go:embed plugin.yaml
var manifestYAML []byte

func init() {
	plugins.Register(&Plugin{})
}

// Plugin implements sdk.Plugin for MongoDB wire protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.MustParseManifest(manifestYAML)
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
	if v, exists := config["blocked_ops"]; exists {
		switch items := v.(type) {
		case []string:
		case []any:
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("blocked_ops must contain strings, got %T", item)
				}
			}
		default:
			return fmt.Errorf("blocked_ops must be a list of strings, got %T", items)
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
	if v, ok := config["blocked_ops"]; ok {
		switch items := v.(type) {
		case []string:
			insp.BlockedOps = items
		case []any:
			for _, item := range items {
				if s, ok := item.(string); ok {
					insp.BlockedOps = append(insp.BlockedOps, strings.ToLower(s))
				}
			}
		}
	}
	insp.buildLookup()
	return insp, nil
}

// buildLookup builds the internal lookup map for blocked operations.
func (insp *Inspector) buildLookup() {
	insp.blockedOpsMap = make(map[string]struct{})
	for _, op := range insp.BlockedOps {
		insp.blockedOpsMap[strings.ToLower(strings.TrimSpace(op))] = struct{}{}
	}
}

// SelfTest verifies that a MongoDB OP_MSG with an authentication error triggers OnAuthFailure.
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
		ServiceName:   "selftest-mongodb",
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

	// Synthetic client: send a minimal OP_MSG (opcode 2013)
	go func() {
		msg := buildOpMsg(map[string]any{"hello": 1})
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write(msg)
		var buf [512]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(buf[:])
		_ = clientA.Close()
	}()

	// Synthetic server: read OP_MSG, reply with auth error response
	go func() {
		var lenBuf [4]byte
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(upB, lenBuf[:]); err != nil {
			return
		}
		msgLen := int(binary.LittleEndian.Uint32(lenBuf[:]))
		rest := make([]byte, msgLen-4)
		_, _ = io.ReadFull(upB, rest)

		// Send OP_MSG reply with {ok:0, code:18, errmsg:"Authentication failed"}
		reply := buildOpMsg(map[string]any{
			"ok":     int32(0),
			"code":   int32(18),
			"errmsg": "Authentication failed.",
		})
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write(reply)
	}()

	select {
	case <-done:
		mu.Lock()
		triggered := authFailureTriggered
		mu.Unlock()
		if !triggered {
			return errors.New("self-test failed: MongoDB auth error did not trigger OnAuthFailure")
		}
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("self-test timed out after 3s")
	}
}

// Inspector inspects MongoDB wire protocol messages.
type Inspector struct {
	MaxAuthFailures int
	BlockedOps      []string // e.g. ["drop", "dropDatabase", "shutdown"]
	blockedOpsMap   map[string]struct{}
}

// Run proxies MongoDB wire protocol, inspecting OP_MSG frames for auth failures and blocked ops.
func (insp *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	var bytesIn, bytesOut atomic.Int64

	result := func(err error) sdk.ProxyResult {
		return sdk.ProxyResult{BytesIn: bytesIn.Load(), BytesOut: bytesOut.Load(), Err: err}
	}

	// Build blocked ops lookup map
	if insp.blockedOpsMap == nil {
		insp.blockedOpsMap = make(map[string]struct{})
		for _, op := range insp.BlockedOps {
			insp.blockedOpsMap[strings.ToLower(op)] = struct{}{}
		}
	}

	for {
		// Read MongoDB MsgHeader (16 bytes)
		client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		var header [16]byte
		if _, err := io.ReadFull(client, header[:]); err != nil {
			return result(err), false, "", nil
		}
		bytesIn.Add(16)

		msgLen := int(binary.LittleEndian.Uint32(header[0:4]))
		if msgLen < 16 || msgLen > 48*1024*1024 { // 48 MB max BSON document
			return result(nil), true, "invalid mongodb message length", nil
		}

		opCode := int32(binary.LittleEndian.Uint32(header[12:16]))

		body := make([]byte, msgLen-16)
		if _, err := io.ReadFull(client, body); err != nil {
			return result(err), false, "", nil
		}
		bytesIn.Add(int64(len(body)))

		// Inspect OP_MSG (2013) for blocked operations
		if opCode == 2013 && len(insp.BlockedOps) > 0 {
			if cmd, found := extractOpMsgCommandName(body); found {
				if _, blocked := insp.blockedOpsMap[strings.ToLower(cmd)]; blocked {
					if ctx != nil {
						ctx.OnSecurityEvent("blocked", "blocked_mongodb_op_"+cmd)
					}
					return result(nil), true, "blocked mongodb operation: " + cmd, nil
				}
			}
		}

		// Forward to upstream
		upstream.SetWriteDeadline(time.Now().Add(30 * time.Second))
		full := append(header[:], body...)
		if _, err := upstream.Write(full); err != nil {
			return result(err), false, "", nil
		}
		bytesOut.Add(int64(len(full)))

		// Read upstream response
		upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
		var respHeader [16]byte
		if _, err := io.ReadFull(upstream, respHeader[:]); err != nil {
			return result(err), false, "", nil
		}
		bytesOut.Add(16)

		respLen := int(binary.LittleEndian.Uint32(respHeader[0:4]))
		if respLen < 16 || respLen > 48*1024*1024 {
			return result(nil), true, "invalid mongodb response length", nil
		}
		respBody := make([]byte, respLen-16)
		if _, err := io.ReadFull(upstream, respBody); err != nil {
			return result(err), false, "", nil
		}
		bytesOut.Add(int64(len(respBody)))

		respOpCode := int32(binary.LittleEndian.Uint32(respHeader[12:16]))

		// Check OP_MSG response for authentication errors (error codes 18, 334)
		if respOpCode == 2013 {
			if isAuthError(respBody) {
				if ctx != nil {
					ctx.OnAuthFailure()
					ctx.OnSecurityEvent("auth_failure", "mongodb_auth_failed")
				}
			}
		}

		// Forward response to client
		client.SetWriteDeadline(time.Now().Add(30 * time.Second))
		fullResp := append(respHeader[:], respBody...)
		if _, err := client.Write(fullResp); err != nil {
			return result(err), false, "", nil
		}
	}
}

// buildOpMsg constructs a minimal MongoDB OP_MSG frame for a given BSON-like map.
// For self-test purposes only — encodes a small subset of BSON.
func buildOpMsg(doc map[string]any) []byte {
	bson := encodeBSONDoc(doc)
	// OP_MSG body: flagBits (4 bytes) + section kind 0 (1 byte) + bson
	body := make([]byte, 4+1+len(bson))
	binary.LittleEndian.PutUint32(body[0:4], 0) // flagBits
	body[4] = 0                                  // section kind: Body
	copy(body[5:], bson)

	total := 16 + len(body)
	msg := make([]byte, total)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(total))
	binary.LittleEndian.PutUint32(msg[4:8], 0)    // requestID
	binary.LittleEndian.PutUint32(msg[8:12], 0)   // responseTo
	binary.LittleEndian.PutUint32(msg[12:16], uint32(2013)) // OP_MSG
	copy(msg[16:], body)
	return msg
}

// encodeBSONDoc encodes a simple map as BSON. Supports string, int32, and int types only.
func encodeBSONDoc(doc map[string]any) []byte {
	var elements []byte
	for k, v := range doc {
		key := append([]byte(k), 0x00)
		switch val := v.(type) {
		case string:
			// BSON string: type 0x02
			strBytes := append([]byte(val), 0x00)
			var lenBuf [4]byte
			binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(strBytes)))
			elements = append(elements, 0x02)
			elements = append(elements, key...)
			elements = append(elements, lenBuf[:]...)
			elements = append(elements, strBytes...)
		case int32:
			// BSON int32: type 0x10
			var numBuf [4]byte
			binary.LittleEndian.PutUint32(numBuf[:], uint32(val))
			elements = append(elements, 0x10)
			elements = append(elements, key...)
			elements = append(elements, numBuf[:]...)
		case int:
			var numBuf [4]byte
			binary.LittleEndian.PutUint32(numBuf[:], uint32(int32(val)))
			elements = append(elements, 0x10)
			elements = append(elements, key...)
			elements = append(elements, numBuf[:]...)
		}
	}

	docLen := 4 + len(elements) + 1 // int32 size + elements + 0x00 terminator
	out := make([]byte, docLen)
	binary.LittleEndian.PutUint32(out[0:4], uint32(docLen))
	copy(out[4:], elements)
	out[docLen-1] = 0x00
	return out
}

// extractOpMsgCommandName parses the command name from the BSON body document in an OP_MSG section.
// It skips metadata keys (e.g. keys starting with '$', 'lsid', etc.) to find the actual command name.
func extractOpMsgCommandName(body []byte) (string, bool) {
	if len(body) < 5 {
		return "", false
	}
	// Skip flagBits (4 bytes) and section kind (1 byte)
	bson := body[5:]
	if len(bson) < 4 {
		return "", false
	}
	docLen := int(binary.LittleEndian.Uint32(bson[0:4]))
	if docLen < 5 || docLen > len(bson) {
		return "", false
	}
	pos := 4
	for pos < docLen-1 {
		elemType := bson[pos]
		pos++
		// Read key (null-terminated)
		start := pos
		for pos < docLen && bson[pos] != 0x00 {
			pos++
		}
		if pos >= docLen {
			return "", false
		}
		key := string(bson[start:pos])
		pos++ // skip null terminator

		keyLower := strings.ToLower(key)
		if !strings.HasPrefix(keyLower, "$") && keyLower != "lsid" && keyLower != "apiversion" && keyLower != "txnnumber" && keyLower != "autocommit" {
			return keyLower, true
		}

		// Skip value based on elemType to continue to next key
		switch elemType {
		case 0x01: // double
			pos += 8
		case 0x02: // string
			if pos+4 > docLen {
				return "", false
			}
			strLen := int(binary.LittleEndian.Uint32(bson[pos : pos+4]))
			pos += 4 + strLen
		case 0x03, 0x04: // document or array
			if pos+4 > docLen {
				return "", false
			}
			subLen := int(binary.LittleEndian.Uint32(bson[pos : pos+4]))
			pos += subLen
		case 0x05: // binary
			if pos+4 > docLen {
				return "", false
			}
			binLen := int(binary.LittleEndian.Uint32(bson[pos : pos+4]))
			pos += 4 + 1 + binLen
		case 0x07: // objectid
			pos += 12
		case 0x08: // bool
			pos += 1
		case 0x09, 0x11, 0x12: // datetime, timestamp, int64
			pos += 8
		case 0x0a: // null
			// 0 bytes
		case 0x10: // int32
			pos += 4
		case 0x13: // decimal128
			pos += 16
		default:
			return "", false
		}
	}
	return "", false
}

// isAuthError checks if an OP_MSG response body contains an authentication error code.
func isAuthError(body []byte) bool {
	// Look for "code" field in BSON with value 18 (AuthenticationFailed) or 334 (SASL conversation)
	if len(body) < 5 {
		return false
	}
	bson := body[5:] // skip flagBits + section kind
	if len(bson) < 4 {
		return false
	}
	pos := 4
	for pos+1 < len(bson) {
		elemType := bson[pos]
		pos++
		// Read key
		start := pos
		for pos < len(bson) && bson[pos] != 0x00 {
			pos++
		}
		if pos >= len(bson) {
			break
		}
		key := string(bson[start:pos])
		pos++ // skip null terminator

		switch elemType {
		case 0x10: // int32
			if pos+4 > len(bson) {
				return false
			}
			val := int32(binary.LittleEndian.Uint32(bson[pos : pos+4]))
			pos += 4
			if strings.ToLower(key) == "code" && (val == 18 || val == 334 || val == 11) {
				return true
			}
		case 0x12: // int64
			if pos+8 > len(bson) {
				return false
			}
			val := int64(binary.LittleEndian.Uint64(bson[pos : pos+8]))
			pos += 8
			if strings.ToLower(key) == "code" && (val == 18 || val == 334 || val == 11) {
				return true
			}
		case 0x01: // float64
			pos += 8
		case 0x02: // string
			if pos+4 > len(bson) {
				return false
			}
			strLen := int(binary.LittleEndian.Uint32(bson[pos : pos+4]))
			pos += 4 + strLen
		case 0x08: // bool
			pos++
		case 0x00: // end of document
			return false
		default:
			return false
		}
	}
	return false
}

// isAuthOk checks if an OP_MSG response body contains {ok: 1}.
func isAuthOk(body []byte) bool {
	if len(body) < 5 {
		return false
	}
	bson := body[5:]
	if len(bson) < 4 {
		return false
	}
	pos := 4
	for pos+1 < len(bson) {
		elemType := bson[pos]
		pos++
		start := pos
		for pos < len(bson) && bson[pos] != 0x00 {
			pos++
		}
		if pos >= len(bson) {
			break
		}
		key := string(bson[start:pos])
		pos++

		switch elemType {
		case 0x10: // int32
			if pos+4 > len(bson) {
				return false
			}
			val := int32(binary.LittleEndian.Uint32(bson[pos : pos+4]))
			pos += 4
			if strings.ToLower(key) == "ok" && val == 1 {
				return true
			}
		case 0x01: // float64
			if pos+8 > len(bson) {
				return false
			}
			// MongoDB sends ok as float64 1.0
			bits := binary.LittleEndian.Uint64(bson[pos : pos+8])
			pos += 8
			if strings.ToLower(key) == "ok" && bits == 0x3FF0000000000000 { // 1.0
				return true
			}
		case 0x02: // string
			if pos+4 > len(bson) {
				return false
			}
			strLen := int(binary.LittleEndian.Uint32(bson[pos : pos+4]))
			pos += 4 + strLen
		case 0x08: // bool
			pos++
		case 0x12: // int64
			pos += 8
		case 0x00:
			return false
		default:
			return false
		}
	}
	return false
}
