package mqtt

import (
	"io"
	"net"
	"testing"
)

func TestMQTTPlugin_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("mqtt SelfTest failed: %v", err)
	}
}

func TestMQTTPlugin_ManifestAndConfig(t *testing.T) {
	p := &Plugin{}
	m := p.Manifest()
	if m.Name != "mqtt" {
		t.Errorf("expected mqtt, got %s", m.Name)
	}

	cfg := map[string]any{
		"blocked_client_id_prefixes": []string{"bot-"},
		"max_client_id_len":          64,
	}
	if err := p.ValidateConfig(cfg); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	insp, err := p.CreateInspector(cfg)
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}

func buildMQTTConnect(clientID string) []byte {
	remLen := 10 + 2 + len(clientID)
	pkt := []byte{0x10, byte(remLen)}
	// Protocol Name: "MQTT"
	pkt = append(pkt, 0x00, 0x04, 'M', 'Q', 'T', 'T')
	// Protocol Level: 4 (MQTT 3.1.1)
	pkt = append(pkt, 0x04)
	// Connect Flags: CleanSession
	pkt = append(pkt, 0x02)
	// KeepAlive: 60s
	pkt = append(pkt, 0x00, 0x3C)
	// Client ID
	pkt = append(pkt, byte(len(clientID)>>8), byte(len(clientID)))
	pkt = append(pkt, []byte(clientID)...)
	return pkt
}

func TestMQTT_Run_AllowAndProxy(t *testing.T) {
	insp := &Inspector{
		BlockedClientIDPrefixes: []string{"bot-"},
		MaxClientIDLen:          64,
	}

	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, blocked, reason, err := insp.Run(nil, clientConn, upConn)
		if blocked {
			t.Errorf("expected allowed, got blocked with reason: %s", reason)
		}
		if err != nil && err != io.EOF {
			t.Errorf("unexpected error: %v", err)
		}
	}()

	// Client writes CONNECT packet
	connectPkt := buildMQTTConnect("device-thermostat-1")
	go func() {
		_, _ = clientPeer.Write(connectPkt)
	}()

	// Upstream reads CONNECT packet forwarded by inspector
	readBuf := make([]byte, len(connectPkt))
	if _, err := io.ReadFull(upPeer, readBuf); err != nil {
		t.Fatalf("upstream failed reading CONNECT: %v", err)
	}
	if string(readBuf) != string(connectPkt) {
		t.Errorf("upstream received different packet than sent")
	}

	// Upstream responds with CONNACK (0x20, 0x02, 0x00, 0x00 = success)
	connack := []byte{0x20, 0x02, 0x00, 0x00}
	go func() {
		_, _ = upPeer.Write(connack)
	}()

	// Client reads CONNACK
	respBuf := make([]byte, len(connack))
	if _, err := io.ReadFull(clientPeer, respBuf); err != nil {
		t.Fatalf("client failed reading CONNACK: %v", err)
	}
	if string(respBuf) != string(connack) {
		t.Errorf("client received different CONNACK than sent")
	}

	// Clean shutdown
	_ = clientPeer.Close()
	_ = upPeer.Close()
	<-done
}

func TestMQTT_Run_BlockedClientIDPrefix(t *testing.T) {
	insp := &Inspector{
		BlockedClientIDPrefixes: []string{"bot-", "malicious-"},
		MaxClientIDLen:          64,
	}

	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, blocked, reason, _ := insp.Run(nil, clientConn, upConn)
		if !blocked {
			t.Errorf("expected blocked=true for bot- client ID")
		}
		if reason == "" {
			t.Errorf("expected non-empty block reason")
		}
	}()

	// Client writes blocked CONNECT
	go func() {
		_, _ = clientPeer.Write(buildMQTTConnect("bot-crawler-99"))
	}()

	// Client should receive MQTT CONNACK return code 5 (Not authorized: 0x20, 0x02, 0x00, 0x05)
	connack := make([]byte, 4)
	if _, err := io.ReadFull(clientPeer, connack); err != nil {
		t.Fatalf("failed reading rejection connack: %v", err)
	}
	if connack[0] != 0x20 || connack[3] != 0x05 {
		t.Errorf("expected CONNACK code 5, got %v", connack)
	}

	<-done
}

func TestMQTT_Run_MaxClientIDLen(t *testing.T) {
	insp := &Inspector{
		MaxClientIDLen: 10,
	}

	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, blocked, reason, _ := insp.Run(nil, clientConn, upConn)
		if !blocked {
			t.Errorf("expected blocked=true for oversized client ID")
		}
		if reason == "" {
			t.Errorf("expected non-empty block reason")
		}
	}()

	// 15-char client ID exceeds max length 10
	go func() {
		_, _ = clientPeer.Write(buildMQTTConnect("too-long-client-id"))
	}()

	// Client should receive MQTT CONNACK return code 2 (Identifier rejected: 0x20, 0x02, 0x00, 0x02)
	connack := make([]byte, 4)
	if _, err := io.ReadFull(clientPeer, connack); err != nil {
		t.Fatalf("failed reading rejection connack: %v", err)
	}
	if connack[0] != 0x20 || connack[3] != 0x02 {
		t.Errorf("expected CONNACK code 2 (identifier rejected), got %v", connack)
	}

	<-done
}

func TestMQTT_Run_NonConnectInitialPacket(t *testing.T) {
	insp := &Inspector{}

	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	upConn, upPeer := net.Pipe()
	defer upConn.Close()
	defer upPeer.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Client sends PINGREQ (packet type 12 = 0xC0) instead of CONNECT (1)
		_, blocked, reason, _ := insp.Run(nil, clientConn, upConn)
		if !blocked {
			t.Errorf("expected blocked=true for non-CONNECT initial packet")
		}
		if reason == "" {
			t.Errorf("expected non-empty block reason")
		}
	}()

	go func() {
		_, _ = clientPeer.Write([]byte{0xC0, 0x00})
	}()

	<-done
}
