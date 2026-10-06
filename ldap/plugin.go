package ldap

import (
	_ "embed"
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

//go:embed plugin.yaml
var manifestYAML []byte

func init() {
	plugins.Register(&Plugin{})
}

// LDAP Protocol Op Tags (Application Class)
const (
	tagBindRequest      = 0x60 // APPLICATION 0
	tagBindResponse     = 0x61 // APPLICATION 1
	tagUnbindRequest    = 0x42 // APPLICATION 2
	tagSearchRequest    = 0x63 // APPLICATION 3
	tagSearchResultDone = 0x65 // APPLICATION 5

	// LDAP Result Codes
	resultSuccess                  = 0
	resultOperationsError          = 1
	resultInvalidCredentials       = 49
	resultInsufficientAccessRights = 50
	resultUnwillingToPerform       = 53
)

// Plugin implements sdk.Plugin for LDAPv3 protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.MustParseManifest(manifestYAML)
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	if v, exists := config["blocked_dns"]; exists {
		switch items := v.(type) {
		case []string:
		case []any:
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("blocked_dns must be a list of strings")
				}
			}
		default:
			return fmt.Errorf("blocked_dns must be a list of strings, got %T", v)
		}
	}
	if v, exists := config["allowed_base_dns"]; exists {
		switch items := v.(type) {
		case []string:
		case []any:
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("allowed_base_dns must be a list of strings")
				}
			}
		default:
			return fmt.Errorf("allowed_base_dns must be a list of strings, got %T", v)
		}
	}
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	insp := &Inspector{}
	if config == nil {
		return insp, nil
	}
	if v, ok := config["blocked_dns"]; ok {
		switch items := v.(type) {
		case []string:
			insp.BlockedDNs = items
		case []any:
			for _, item := range items {
				if s, ok := item.(string); ok {
					insp.BlockedDNs = append(insp.BlockedDNs, s)
				}
			}
		}
	}
	if v, ok := config["allowed_base_dns"]; ok {
		switch items := v.(type) {
		case []string:
			insp.AllowedBaseDNs = items
		case []any:
			for _, item := range items {
				if s, ok := item.(string); ok {
					insp.AllowedBaseDNs = append(insp.AllowedBaseDNs, s)
				}
			}
		}
	}
	return insp, nil
}

// SelfTest verifies that an LDAP BindResponse with invalidCredentials (49) triggers OnAuthFailure.
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
		ServiceName:   "selftest-ldap",
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

	// Upstream server mock: read request, send BindResponse with resultCode 49 (invalidCredentials)
	go func() {
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = readBERMessage(upB)

		// Send BindResponse with resultCode 49
		resp := buildBindResponse(1, resultInvalidCredentials, "Invalid credentials")
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write(resp)
	}()

	// Synthetic client: send BindRequest
	_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
	bindReq := buildBindRequest(1, "cn=admin,dc=example,dc=com", "wrongpass")
	_, _ = clientA.Write(bindReq)

	// Read BindResponse from client
	var respBuf [512]byte
	_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = clientA.Read(respBuf[:])
	_ = clientA.Close()

	select {
	case <-done:
		mu.Lock()
		triggered := authFailureTriggered
		mu.Unlock()
		if !triggered {
			return errors.New("self-test failed: LDAP invalid credentials did not trigger OnAuthFailure")
		}
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("self-test timed out after 3s")
	}
}

// Inspector inspects LDAPv3 messages for authentication errors and unauthorized DNs.
type Inspector struct {
	BlockedDNs     []string
	AllowedBaseDNs []string
}

// Run proxies LDAPv3 traffic, inspecting BindRequest, SearchRequest, and BindResponse.
func (insp *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	var bytesIn, bytesOut atomic.Int64

	result := func(err error) sdk.ProxyResult {
		return sdk.ProxyResult{BytesIn: bytesIn.Load(), BytesOut: bytesOut.Load(), Err: err}
	}

	for {
		// Read BER message from client
		client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		msgData, err := readBERMessage(client)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return result(nil), false, "", nil
			}
			return result(err), false, "", nil
		}
		bytesIn.Add(int64(len(msgData)))

		msgID, opTag, opBody, parseErr := parseLDAPMessage(msgData)
		if parseErr == nil {
			// Check if DN is blocked in BindRequest or SearchRequest
			if opTag == tagBindRequest || opTag == tagSearchRequest {
				dn := extractDNFromOp(opTag, opBody)
				if dn != "" {
					if insp.isDNBlocked(dn) {
						if ctx != nil {
							ctx.OnSecurityEvent("blocked", "ldap_blocked_dn_"+dn)
						}
						// Respond with InsufficientAccessRights (50)
						errResp := buildBindResponse(msgID, resultInsufficientAccessRights, "Access denied by RouteWarden")
						client.SetWriteDeadline(time.Now().Add(5 * time.Second))
						_, _ = client.Write(errResp)
						bytesOut.Add(int64(len(errResp)))
						return result(nil), true, "blocked ldap dn: " + dn, nil
					}
				}
			}
		}

		// Forward to upstream
		upstream.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := upstream.Write(msgData); err != nil {
			return result(err), false, "", nil
		}

		// Read upstream response
		upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
		respData, err := readBERMessage(upstream)
		if err != nil {
			return result(err), false, "", nil
		}
		bytesOut.Add(int64(len(respData)))

		// Inspect BindResponse for auth failure
		_, respOpTag, respOpBody, rErr := parseLDAPMessage(respData)
		if rErr == nil && respOpTag == tagBindResponse {
			resCode := extractResultCode(respOpBody)
			switch resCode {
			case resultInvalidCredentials:
				if ctx != nil {
					ctx.OnAuthFailure()
					ctx.OnSecurityEvent("auth_failure", "ldap_invalid_credentials")
				}
			case resultSuccess:
				// Once authenticated, switch to raw proxy for high throughput
				client.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := client.Write(respData); err != nil {
					return result(err), false, "", nil
				}
				client.SetDeadline(time.Time{})
				upstream.SetDeadline(time.Time{})
				res := protocol.Proxy(client, upstream)
				bytesIn.Add(res.BytesIn)
				bytesOut.Add(res.BytesOut)
				return result(nil), false, "", nil
			}
		}

		// Forward response to client
		client.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := client.Write(respData); err != nil {
			return result(err), false, "", nil
		}
	}
}

func (insp *Inspector) isDNBlocked(dn string) bool {
	dnNorm := normalizeDN(dn)
	for _, b := range insp.BlockedDNs {
		if normalizeDN(b) == dnNorm {
			return true
		}
	}
	if len(insp.AllowedBaseDNs) > 0 {
		allowed := false
		for _, base := range insp.AllowedBaseDNs {
			baseNorm := normalizeDN(base)
			if dnNorm == baseNorm || strings.HasSuffix(dnNorm, ","+baseNorm) {
				allowed = true
				break
			}
		}
		if !allowed {
			return true
		}
	}
	return false
}

func normalizeDN(dn string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(dn)), ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return strings.Join(parts, ",")
}

// readBERMessage reads a complete ASN.1 BER TLV message from conn.
func readBERMessage(r io.Reader) ([]byte, error) {
	var tagBuf [1]byte
	if _, err := io.ReadFull(r, tagBuf[:]); err != nil {
		return nil, err
	}
	tag := tagBuf[0]

	// Read length
	var lenByte [1]byte
	if _, err := io.ReadFull(r, lenByte[:]); err != nil {
		return nil, err
	}

	var length int
	var lenHeader []byte
	lenHeader = append(lenHeader, lenByte[0])

	if lenByte[0]&0x80 == 0 {
		length = int(lenByte[0])
	} else {
		numBytes := int(lenByte[0] & 0x7F)
		if numBytes > 4 || numBytes == 0 {
			return nil, fmt.Errorf("unsupported BER length byte count: %d", numBytes)
		}
		lenBuf := make([]byte, numBytes)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return nil, err
		}
		lenHeader = append(lenHeader, lenBuf...)
		for _, b := range lenBuf {
			length = (length << 8) | int(b)
		}
	}

	if length < 0 || length > 16*1024*1024 { // 16 MB max
		return nil, fmt.Errorf("BER message length invalid: %d", length)
	}

	val := make([]byte, length)
	if _, err := io.ReadFull(r, val); err != nil {
		return nil, err
	}

	full := make([]byte, 0, 1+len(lenHeader)+length)
	full = append(full, tag)
	full = append(full, lenHeader...)
	full = append(full, val...)
	return full, nil
}

// parseLDAPMessage parses: LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE, ... }
func parseLDAPMessage(data []byte) (msgID int64, opTag byte, opBody []byte, err error) {
	if len(data) < 2 || data[0] != 0x30 {
		return 0, 0, nil, errors.New("not an LDAP SEQUENCE")
	}
	// Decode outer SEQUENCE length
	offset := 1
	seqLen, n := decodeBERLength(data[offset:])
	if n <= 0 {
		return 0, 0, nil, errors.New("invalid BER sequence length")
	}
	offset += n
	if offset+seqLen > len(data) {
		return 0, 0, nil, errors.New("truncated LDAP message")
	}

	// 1. MessageID: INTEGER (tag 0x02)
	if offset >= len(data) || data[offset] != 0x02 {
		return 0, 0, nil, errors.New("missing messageID INTEGER")
	}
	offset++
	idLen, n := decodeBERLength(data[offset:])
	offset += n
	if idLen <= 0 || idLen > 8 || offset+idLen > len(data) {
		return 0, 0, nil, errors.New("invalid messageID length")
	}
	for i := 0; i < idLen; i++ {
		msgID = (msgID << 8) | int64(data[offset+i])
	}
	offset += idLen

	// 2. ProtocolOp CHOICE
	if offset >= len(data) {
		return 0, 0, nil, errors.New("missing protocolOp")
	}
	opTag = data[offset]
	offset++
	opLen, n := decodeBERLength(data[offset:])
	offset += n
	if offset+opLen > len(data) {
		return 0, 0, nil, errors.New("truncated protocolOp")
	}
	opBody = data[offset : offset+opLen]
	return msgID, opTag, opBody, nil
}

func decodeBERLength(b []byte) (length int, bytesRead int) {
	if len(b) == 0 {
		return 0, 0
	}
	if b[0]&0x80 == 0 {
		return int(b[0]), 1
	}
	numBytes := int(b[0] & 0x7F)
	if numBytes == 0 || numBytes > 4 || len(b) < 1+numBytes {
		return 0, 0
	}
	for i := 1; i <= numBytes; i++ {
		length = (length << 8) | int(b[i])
	}
	if length < 0 {
		return 0, 0
	}
	return length, 1 + numBytes
}

func encodeBERLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	if length < 256 {
		return []byte{0x81, byte(length)}
	}
	return []byte{0x82, byte(length >> 8), byte(length & 0xFF)}
}

// extractDNFromOp extracts the name/baseObject OCTET STRING from a BindRequest or SearchRequest.
func extractDNFromOp(opTag byte, body []byte) string {
	offset := 0
	if opTag == tagBindRequest {
		// BindRequest ::= SEQUENCE { version INTEGER, name LDAPDN (OCTET STRING 0x04), ... }
		if len(body) < 3 || body[0] != 0x02 { // version INTEGER
			return ""
		}
		verLen := int(body[1])
		offset = 2 + verLen
	}
	// At name/baseObject (OCTET STRING 0x04)
	if offset < len(body) && body[offset] == 0x04 {
		offset++
		dnLen, n := decodeBERLength(body[offset:])
		offset += n
		if offset+dnLen <= len(body) {
			return string(body[offset : offset+dnLen])
		}
	}
	return ""
}

// extractResultCode parses LDAPResult ::= SEQUENCE { resultCode ENUMERATED (0x0A), ... }
func extractResultCode(body []byte) int {
	if len(body) < 3 || body[0] != 0x0A { // ENUMERATED
		return -1
	}
	codeLen := int(body[1])
	if 2+codeLen > len(body) {
		return -1
	}
	code := 0
	for i := 0; i < codeLen; i++ {
		code = (code << 8) | int(body[2+i])
	}
	return code
}

// buildBindRequest encodes an LDAP BindRequest frame.
func buildBindRequest(msgID int64, dn, password string) []byte {
	// Simple authentication: [0] OCTET STRING
	authPayload := append([]byte{0x80, byte(len(password))}, []byte(password)...)

	// BindRequest payload: version(3) + name + auth
	version := []byte{0x02, 0x01, 0x03} // version 3
	dnBytes := append(append([]byte{0x04}, encodeBERLength(len(dn))...), []byte(dn)...)

	reqPayload := append(version, dnBytes...)
	reqPayload = append(reqPayload, authPayload...)

	opBytes := append(append([]byte{tagBindRequest}, encodeBERLength(len(reqPayload))...), reqPayload...)

	// MsgID INTEGER
	msgIDBytes := []byte{0x02, 0x01, byte(msgID)}

	seqPayload := append(msgIDBytes, opBytes...)
	return append(append([]byte{0x30}, encodeBERLength(len(seqPayload))...), seqPayload...)
}

// buildBindResponse encodes an LDAP BindResponse frame.
func buildBindResponse(msgID int64, resultCode int, diagMessage string) []byte {
	// LDAPResult: resultCode ENUMERATED, matchedDN OCTET STRING, diagnosticMessage OCTET STRING
	resCodeBytes := []byte{0x0A, 0x01, byte(resultCode)}
	matchedDN := []byte{0x04, 0x00}
	diagBytes := append(append([]byte{0x04}, encodeBERLength(len(diagMessage))...), []byte(diagMessage)...)

	resPayload := append(resCodeBytes, matchedDN...)
	resPayload = append(resPayload, diagBytes...)

	opBytes := append(append([]byte{tagBindResponse}, encodeBERLength(len(resPayload))...), resPayload...)
	msgIDBytes := []byte{0x02, 0x01, byte(msgID)}

	seqPayload := append(msgIDBytes, opBytes...)
	return append(append([]byte{0x30}, encodeBERLength(len(seqPayload))...), seqPayload...)
}
