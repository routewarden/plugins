package mysql

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func TestMySQLPlugin_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("mysql SelfTest failed: %v", err)
	}
}

func TestMySQLPlugin_ManifestAndConfig(t *testing.T) {
	p := &Plugin{}
	m := p.Manifest()
	if m.Name != "mysql" {
		t.Errorf("expected mysql, got %s", m.Name)
	}

	if err := p.ValidateConfig(map[string]any{"max_auth_failures": 5}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	insp, err := p.CreateInspector(nil)
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}

func makeMySQLPacket(seq byte, payload []byte) []byte {
	pkt := make([]byte, 4+len(payload))
	pkt[0] = byte(len(payload))
	pkt[1] = byte(len(payload) >> 8)
	pkt[2] = byte(len(payload) >> 16)
	pkt[3] = seq
	copy(pkt[4:], payload)
	return pkt
}

func TestMySQL_Run_SuccessfulHandshakeAndProxy(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	insp := &Inspector{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, blocked, _, _ := insp.Run(nil, clientConn, upConn)
		if blocked {
			t.Errorf("expected allowed handshake")
		}
	}()

	// 1. Upstream sends initial handshake (seq 0)
	handshakePkt := makeMySQLPacket(0, []byte("\n8.0.32\x00"))
	go func() {
		_, _ = upPeer.Write(handshakePkt)
	}()

	// Client reads handshake
	readHandshake := make([]byte, len(handshakePkt))
	if _, err := io.ReadFull(clientPeer, readHandshake); err != nil {
		t.Fatalf("client failed reading handshake: %v", err)
	}

	// 2. Client sends HandshakeResponse41 (seq 1, no SSL)
	clientRespPayload := make([]byte, 32)
	// caps = 0 (no SSL)
	clientRespPkt := makeMySQLPacket(1, clientRespPayload)
	go func() {
		_, _ = clientPeer.Write(clientRespPkt)
	}()

	// Upstream reads HandshakeResponse41
	readClientResp := make([]byte, len(clientRespPkt))
	if _, err := io.ReadFull(upPeer, readClientResp); err != nil {
		t.Fatalf("upstream failed reading client response: %v", err)
	}

	// 3. Upstream sends OK packet (seq 2, payload starting with 0x00)
	okPkt := makeMySQLPacket(2, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
	go func() {
		_, _ = upPeer.Write(okPkt)
	}()

	// Client reads OK packet
	readOK := make([]byte, len(okPkt))
	if _, err := io.ReadFull(clientPeer, readOK); err != nil {
		t.Fatalf("client failed reading OK packet: %v", err)
	}

	// 4. Now in raw proxy mode: client sends COM_QUERY, upstream receives it
	queryPayload := []byte("SELECT 1")
	go func() {
		_, _ = clientPeer.Write(queryPayload)
	}()

	readQuery := make([]byte, len(queryPayload))
	if _, err := io.ReadFull(upPeer, readQuery); err != nil {
		t.Fatalf("upstream failed reading proxied query: %v", err)
	}
	if string(readQuery) != "SELECT 1" {
		t.Errorf("expected 'SELECT 1', got %s", string(readQuery))
	}

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}

func TestMySQL_Run_SSLHandshake(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	insp := &Inspector{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, blocked, _, _ := insp.Run(nil, clientConn, upConn)
		if blocked {
			t.Errorf("expected allowed SSL handshake")
		}
	}()

	// Upstream sends handshake
	handshakePkt := makeMySQLPacket(0, []byte("\n8.0.32\x00"))
	go func() {
		_, _ = upPeer.Write(handshakePkt)
	}()

	readHandshake := make([]byte, len(handshakePkt))
	_, _ = io.ReadFull(clientPeer, readHandshake)

	// Client sends SSL request packet with CLIENT_SSL bit (0x00000800) set in first 4 bytes of payload
	sslPayload := make([]byte, 32)
	binary.LittleEndian.PutUint32(sslPayload[0:4], 0x00000800)
	sslPkt := makeMySQLPacket(1, sslPayload)
	go func() {
		_, _ = clientPeer.Write(sslPkt)
	}()

	// Upstream receives SSL request packet
	readSSL := make([]byte, len(sslPkt))
	if _, err := io.ReadFull(upPeer, readSSL); err != nil {
		t.Fatalf("upstream failed reading SSL packet: %v", err)
	}

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}

func TestMySQL_Run_AccessDenied1044(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	authFailed := false
	ctx := &sdk.DefaultContext{
		ServiceName:   "mysql-test",
		ClientAddress: "127.0.0.1",
		AuthFailureFunc: func() {
			authFailed = true
		},
	}

	insp := &Inspector{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _, _ = insp.Run(ctx, clientConn, upConn)
	}()

	// Upstream sends handshake
	handshakePkt := makeMySQLPacket(0, []byte("\n8.0.32\x00"))
	go func() {
		_, _ = upPeer.Write(handshakePkt)
	}()

	readHandshake := make([]byte, len(handshakePkt))
	_, _ = io.ReadFull(clientPeer, readHandshake)

	// Client sends response
	clientRespPkt := makeMySQLPacket(1, make([]byte, 32))
	go func() {
		_, _ = clientPeer.Write(clientRespPkt)
	}()

	readResp := make([]byte, len(clientRespPkt))
	_, _ = io.ReadFull(upPeer, readResp)

	// Upstream sends ERR packet with code 1044 (0x14, 0x04)
	errPayload := make([]byte, 3+len("Access denied for database"))
	errPayload[0] = 0xFF
	binary.LittleEndian.PutUint16(errPayload[1:3], 1044)
	copy(errPayload[3:], "Access denied for database")
	errPkt := makeMySQLPacket(2, errPayload)
	go func() {
		_, _ = upPeer.Write(errPkt)
	}()

	readErr := make([]byte, len(errPkt))
	_, _ = io.ReadFull(clientPeer, readErr)

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done

	if !authFailed {
		t.Errorf("expected AuthFailureFunc on MySQL error 1044")
	}
}

func TestMySQL_ValidateConfig(t *testing.T) {
	p := &Plugin{}
	if err := p.ValidateConfig(nil); err != nil {
		t.Errorf("nil config rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"max_auth_failures": "not-an-int"}); err == nil {
		t.Errorf("expected error for non-int max_auth_failures")
	}
}

func TestMySQL_SecurityBoundaries(t *testing.T) {
	// 1. Oversized packet payload length (>4MB) must be rejected
	var oversizedHeader [4]byte
	oversizedHeader[0] = 0x01
	oversizedHeader[1] = 0x00
	oversizedHeader[2] = 0x41 // 4MB + 64KB
	oversizedHeader[3] = 0x00

	r := bytes.NewReader(oversizedHeader[:])
	_, err := readMySQLPacket(r)
	if err == nil || !strings.Contains(err.Error(), "exceeds max 4MB") {
		t.Errorf("expected payload length error for >4MB packet, got: %v", err)
	}

	// 2. Unexpected server packet header terminates handshake safely
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	insp := &Inspector{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		res, blocked, _, _ := insp.Run(nil, clientConn, upConn)
		if blocked {
			t.Errorf("unexpected blocked on unexpected packet")
		}
		if res.Err == nil || !strings.Contains(res.Err.Error(), "unrecognized MySQL packet header") {
			t.Errorf("expected unrecognized MySQL packet header error, got: %v", res.Err)
		}
	}()

	// Upstream sends handshake
	handshakePkt := makeMySQLPacket(0, []byte("\n8.0.32\x00"))
	go func() {
		_, _ = upPeer.Write(handshakePkt)
	}()

	buf := make([]byte, len(handshakePkt))
	_, _ = io.ReadFull(clientPeer, buf)

	// Client sends response
	clientRespPkt := makeMySQLPacket(1, make([]byte, 32))
	go func() {
		_, _ = clientPeer.Write(clientRespPkt)
	}()

	buf = make([]byte, len(clientRespPkt))
	_, _ = io.ReadFull(upPeer, buf)

	// Upstream sends unexpected packet (0x42)
	unexpectedPkt := makeMySQLPacket(2, []byte{0x42, 0x01, 0x02})
	go func() {
		_, _ = upPeer.Write(unexpectedPkt)
	}()

	buf = make([]byte, len(unexpectedPkt))
	_, _ = io.ReadFull(clientPeer, buf)

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}

