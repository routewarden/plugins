package amqp

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestAMQP_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest() failed: %v", err)
	}
}

func TestAMQP_ValidateConfig(t *testing.T) {
	p := &Plugin{}
	if err := p.ValidateConfig(nil); err != nil {
		t.Errorf("nil config should be valid: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"max_auth_failures": 5}); err != nil {
		t.Errorf("valid config failed: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"allowed_vhosts": []any{"/"}}); err != nil {
		t.Errorf("valid vhost config failed: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"max_auth_failures": "bad"}); err == nil {
		t.Error("expected error for non-integer max_auth_failures")
	}
}

func TestAMQP_VHostBlocked(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{AllowedVHosts: []string{"/prod"}}
	done := make(chan struct {
		blocked bool
		reason  string
	}, 1)

	go func() {
		_, blocked, reason, _ := insp.Run(nil, clientB, upA)
		done <- struct {
			blocked bool
			reason  string
		}{blocked, reason}
	}()

	// Upstream server goroutine
	go func() {
		var hdr [8]byte
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(upB, hdr[:]); err != nil {
			return
		}
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write(buildConnectionStart())

		// Read Start-Ok
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := readAMQPFrame(upB); err != nil {
			return
		}

		// Send Connection.Tune
		tunePayload := []byte{0x00, 0x0A, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x3C}
		tuneFrame := buildAMQPFrame(frameMethod, 0, tunePayload)
		_ = upB.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Write(tuneFrame)

		// Read Tune-Ok
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = readAMQPFrame(upB)
	}()

	// Client: send protocol header
	_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = clientA.Write([]byte("AMQP\x00\x00\x09\x01"))

	// Client: read Connection.Start (forwarded), send Start-Ok
	var buf [512]byte
	_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = clientA.Read(buf[:])
	_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = clientA.Write(buildConnectionStartOk("guest", "guest"))

	// Client: read Tune, send Tune-Ok then Connection.Open with vhost "/dev" (not in allowed list)
	_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = clientA.Read(buf[:])
	tuneOk := buildAMQPFrame(frameMethod, 0, []byte{0x00, 0x0A, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x3C})
	_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = clientA.Write(tuneOk)

	// Send Connection.Open with vhost "/dev"
	openPayload := []byte{0x00, 0x0A, 0x00, 0x28, 0x04, '/', 'd', 'e', 'v', 0x00, 0x00}
	openFrame := buildAMQPFrame(frameMethod, 0, openPayload)
	_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = clientA.Write(openFrame)

	// Client: read Connection.Close sent by inspector when vhost is blocked
	var closeBuf [256]byte
	_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = clientA.Read(closeBuf[:])

	select {
	case res := <-done:
		if !res.blocked {
			t.Errorf("expected vhost /dev to be blocked, got blocked=%v reason=%q", res.blocked, res.reason)
		}
	case <-time.After(4 * time.Second):
		t.Error("test timed out")
	}
}
