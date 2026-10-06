package postgres

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func TestPostgresPlugin_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("postgres SelfTest failed: %v", err)
	}
}

func TestPostgresPlugin_ManifestAndConfig(t *testing.T) {
	p := &Plugin{}
	m := p.Manifest()
	if m.Name != "postgres" {
		t.Errorf("expected postgres, got %s", m.Name)
	}

	if err := p.ValidateConfig(map[string]any{"max_auth_failures": 3}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	if err := p.ValidateConfig(map[string]any{"max_auth_failures": "invalid"}); err == nil {
		t.Errorf("invalid config accepted")
	}

	insp, err := p.CreateInspector(map[string]any{"max_auth_failures": 5})
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}

func TestPostgres_Run_SuccessfulAuthAndProxy(t *testing.T) {
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

	// 1. Client sends StartupMessage (len=8, ver=196608)
	var startup [8]byte
	binary.BigEndian.PutUint32(startup[0:4], 8)
	binary.BigEndian.PutUint32(startup[4:8], 196608)
	go func() {
		_, _ = clientPeer.Write(startup[:])
	}()

	// Upstream reads StartupMessage
	var upStartup [8]byte
	if _, err := io.ReadFull(upPeer, upStartup[:]); err != nil {
		t.Fatalf("upstream failed reading startup: %v", err)
	}

	// 2. Upstream sends AuthenticationOk: 'R', len=8, authType=0
	var authOk [9]byte
	authOk[0] = 'R'
	binary.BigEndian.PutUint32(authOk[1:5], 8)
	binary.BigEndian.PutUint32(authOk[5:9], 0)
	go func() {
		_, _ = upPeer.Write(authOk[:])
	}()

	// Client reads AuthenticationOk
	var clientAuthOk [9]byte
	if _, err := io.ReadFull(clientPeer, clientAuthOk[:]); err != nil {
		t.Fatalf("client failed reading auth ok: %v", err)
	}

	// 3. Upstream sends ReadyForQuery: 'Z', len=5, status='I'
	var ready [6]byte
	ready[0] = 'Z'
	binary.BigEndian.PutUint32(ready[1:5], 5)
	ready[5] = 'I'
	go func() {
		_, _ = upPeer.Write(ready[:])
	}()

	// Client reads ReadyForQuery
	var clientReady [6]byte
	if _, err := io.ReadFull(clientPeer, clientReady[:]); err != nil {
		t.Fatalf("client failed reading ready: %v", err)
	}

	// 4. In proxy mode: client sends Query 'Q', upstream receives it
	queryPayload := []byte("Q\x00\x00\x00\x0eSELECT 1;\x00")
	go func() {
		_, _ = clientPeer.Write(queryPayload)
	}()

	readQuery := make([]byte, len(queryPayload))
	if _, err := io.ReadFull(upPeer, readQuery); err != nil {
		t.Fatalf("upstream failed reading query: %v", err)
	}
	if string(readQuery) != string(queryPayload) {
		t.Errorf("upstream received different query")
	}

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}

func TestPostgres_Run_SSLRequestAccepted(t *testing.T) {
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
			t.Errorf("expected allowed SSLRequest")
		}
	}()

	// Client sends SSLRequest (len=8, code=80877103)
	var sslReq [8]byte
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], 80877103)
	go func() {
		_, _ = clientPeer.Write(sslReq[:])
	}()

	// Upstream reads SSLRequest
	var upReq [8]byte
	if _, err := io.ReadFull(upPeer, upReq[:]); err != nil {
		t.Fatalf("upstream failed reading SSLRequest: %v", err)
	}

	// Upstream replies 'S' (SSL accepted)
	go func() {
		_, _ = upPeer.Write([]byte{'S'})
	}()

	// Client reads 'S'
	var clientResp [1]byte
	if _, err := io.ReadFull(clientPeer, clientResp[:]); err != nil {
		t.Fatalf("client failed reading SSL response: %v", err)
	}
	if clientResp[0] != 'S' {
		t.Errorf("expected 'S', got %c", clientResp[0])
	}

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}

func TestPostgres_Run_AuthError28000(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	authFailed := false
	ctx := &sdk.DefaultContext{
		ServiceName:   "pg-test",
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

	// Client sends StartupMessage
	var startup [8]byte
	binary.BigEndian.PutUint32(startup[0:4], 8)
	binary.BigEndian.PutUint32(startup[4:8], 196608)
	go func() {
		_, _ = clientPeer.Write(startup[:])
	}()

	var upStartup [8]byte
	_, _ = io.ReadFull(upPeer, upStartup[:])

	// Upstream sends ErrorResponse with code 28000
	errBody := []byte("SFATAL\x00C28000\x00Minvalid authorization specification\x00\x00")
	var errHeader [5]byte
	errHeader[0] = 'E'
	binary.BigEndian.PutUint32(errHeader[1:5], uint32(len(errBody)+4))
	errPkt := append(errHeader[:], errBody...)
	go func() {
		_, _ = upPeer.Write(errPkt)
	}()

	// Client reads ErrorResponse
	clientErr := make([]byte, len(errPkt))
	_, _ = io.ReadFull(clientPeer, clientErr)

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done

	if !authFailed {
		t.Errorf("expected AuthFailureFunc on Postgres error code 28000")
	}
}

func TestPostgres_Run_GSSENCRequest(t *testing.T) {
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
			t.Errorf("expected allowed GSSENCRequest")
		}
	}()

	// 1. Client sends GSSENCRequest (len=8, code=80877104)
	var gssReq [8]byte
	binary.BigEndian.PutUint32(gssReq[0:4], 8)
	binary.BigEndian.PutUint32(gssReq[4:8], 80877104)
	go func() {
		_, _ = clientPeer.Write(gssReq[:])
	}()

	// Upstream reads GSSENCRequest
	var upReq [8]byte
	if _, err := io.ReadFull(upPeer, upReq[:]); err != nil {
		t.Fatalf("upstream failed reading GSSENCRequest: %v", err)
	}

	// Upstream replies 'N' (declined)
	go func() {
		_, _ = upPeer.Write([]byte{'N'})
	}()

	// Client reads 'N'
	var clientResp [1]byte
	if _, err := io.ReadFull(clientPeer, clientResp[:]); err != nil {
		t.Fatalf("client failed reading GSS response: %v", err)
	}
	if clientResp[0] != 'N' {
		t.Errorf("expected 'N', got %c", clientResp[0])
	}

	// 2. Client then proceeds with standard StartupMessage
	var startup [8]byte
	binary.BigEndian.PutUint32(startup[0:4], 8)
	binary.BigEndian.PutUint32(startup[4:8], 196608)
	go func() {
		_, _ = clientPeer.Write(startup[:])
	}()

	var upStartup [8]byte
	if _, err := io.ReadFull(upPeer, upStartup[:]); err != nil {
		t.Fatalf("upstream failed reading startup: %v", err)
	}

	// Upstream sends AuthenticationOk
	var authOk [9]byte
	authOk[0] = 'R'
	binary.BigEndian.PutUint32(authOk[1:5], 8)
	binary.BigEndian.PutUint32(authOk[5:9], 0)
	go func() {
		_, _ = upPeer.Write(authOk[:])
	}()

	var clientAuthOk [9]byte
	if _, err := io.ReadFull(clientPeer, clientAuthOk[:]); err != nil {
		t.Fatalf("client failed reading auth ok: %v", err)
	}

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}

func TestPostgres_Run_CancelRequest(t *testing.T) {
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
		_, blocked, _, err := insp.Run(nil, clientConn, upConn)
		if blocked || err != nil {
			t.Errorf("expected allowed CancelRequest without error, got blocked=%v err=%v", blocked, err)
		}
	}()

	// Client sends CancelRequest (len=16, code=80877102, PID=1234, Secret=5678)
	var cancelReq [16]byte
	binary.BigEndian.PutUint32(cancelReq[0:4], 16)
	binary.BigEndian.PutUint32(cancelReq[4:8], 80877102)
	binary.BigEndian.PutUint32(cancelReq[8:12], 1234)
	binary.BigEndian.PutUint32(cancelReq[12:16], 5678)
	go func() {
		_, _ = clientPeer.Write(cancelReq[:])
	}()

	// Upstream reads CancelRequest
	var upReq [16]byte
	if _, err := io.ReadFull(upPeer, upReq[:]); err != nil {
		t.Fatalf("upstream failed reading CancelRequest: %v", err)
	}

	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}
