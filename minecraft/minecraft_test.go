package minecraft

import (
	"io"
	"net"
	"testing"
)

func TestMinecraftPlugin_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("minecraft SelfTest failed: %v", err)
	}
}

func TestMinecraft_Run_CleanHandshakeAndProxy(t *testing.T) {
	insp := &Inspector{BlockedProtocolVersions: []int{47}}

	clientConn, proxyClient := net.Pipe()
	proxyUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyUpstream.Close()
	defer upstreamConn.Close()

	done := make(chan error, 1)
	go func() {
		_, blocked, _, err := insp.Run(nil, proxyClient, proxyUpstream)
		if blocked {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- err
	}()

	// Upstream reader
	go func() {
		// Handshake packet
		handshake := make([]byte, 16)
		n, _ := io.ReadFull(upstreamConn, handshake)
		if n > 0 {
			// Read subsequent login packet to verify client stream is NOT EOF'd
			subsequent := make([]byte, 5)
			_, _ = io.ReadFull(upstreamConn, subsequent)
			_, _ = upstreamConn.Write([]byte("PONG"))
		}
		_ = upstreamConn.Close()
	}()

	// Minecraft Handshake (Packet Length: 15, Packet ID: 0, ProtoVer: 760 (1.19.2), Host: "localhost", Port: 25565, NextState: 2)
	// Varint 15 (0x0F), PacketID 0 (0x00), ProtoVer 760 (0xF8, 0x05)
	pkt := []byte{0x0F, 0x00, 0xF8, 0x05, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x63, 0xDD, 0x02}
	_, _ = clientConn.Write(pkt)
	_, _ = clientConn.Write([]byte("LOGIN"))

	resp := make([]byte, 4)
	_, err := io.ReadFull(clientConn, resp)
	if err != nil {
		t.Fatalf("failed reading response: %v", err)
	}
	if string(resp) != "PONG" {
		t.Fatalf("expected PONG, got %s", string(resp))
	}
	_ = clientConn.Close()
	<-done
}

func TestMinecraft_Run_BlockedProtocolVersion(t *testing.T) {
	insp := &Inspector{BlockedProtocolVersions: []int{47}} // Block 1.8 (47)

	clientConn, proxyClient := net.Pipe()
	proxyUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyUpstream.Close()
	defer upstreamConn.Close()

	done := make(chan bool, 1)
	go func() {
		_, blocked, reason, _ := insp.Run(nil, proxyClient, proxyUpstream)
		if blocked && reason != "" {
			done <- true
		} else {
			done <- false
		}
	}()

	// Packet length 5, Packet ID 0, ProtoVer 47 (0x2F)
	pkt := []byte{0x05, 0x00, 0x2F, 0x00, 0x00}
	_, _ = clientConn.Write(pkt)

	if !<-done {
		t.Fatalf("expected blocked protocol version 47")
	}
}
