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

func TestAMQP_InvalidProtocolHeader(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{}
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

	// Client sends invalid protocol header
	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write([]byte("HTTP/1.1"))
	}()

	select {
	case res := <-done:
		if !res.blocked {
			t.Errorf("expected blocked=true for invalid AMQP header, got %v", res.blocked)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test timed out")
	}
}

func TestAMQP_AllowedVHostAndProxy(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{AllowedVHosts: []string{"/prod"}}
	done := make(chan struct {
		blocked bool
	}, 1)

	go func() {
		_, blocked, _, _ := insp.Run(nil, clientB, upA)
		done <- struct {
			blocked bool
		}{blocked}
	}()

	// Upstream server mock
	go func() {
		var hdr [8]byte
		_ = upB.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(upB, hdr[:]); err != nil {
			return
		}
		// Send Connection.Start
		_, _ = upB.Write(buildConnectionStart())

		// Read Start-Ok
		if _, err := readAMQPFrame(upB); err != nil {
			return
		}

		// Send Connection.Tune
		tunePayload := []byte{0x00, 0x0A, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x3C}
		tuneFrame := buildAMQPFrame(frameMethod, 0, tunePayload)
		_, _ = upB.Write(tuneFrame)

		// Read Tune-Ok
		if _, err := readAMQPFrame(upB); err != nil {
			return
		}

		// Read Connection.Open
		if _, err := readAMQPFrame(upB); err != nil {
			return
		}

		// Send Connection.Open-Ok (class 10, method 41 = 0x0029)
		openOkPayload := []byte{0x00, 0x0A, 0x00, 0x29, 0x00}
		openOkFrame := buildAMQPFrame(frameMethod, 0, openOkPayload)
		_, _ = upB.Write(openOkFrame)

		// Post-handshake proxy test
		buf := make([]byte, 4)
		if _, err := io.ReadFull(upB, buf); err == nil && string(buf) == "PING" {
			_, _ = upB.Write([]byte("PONG"))
		}
		_ = upB.Close()
	}()

	// Client mock
	go func() {
		_ = clientA.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = clientA.Write([]byte("AMQP\x00\x00\x09\x01"))

		// Read Connection.Start
		var buf [512]byte
		_, _ = clientA.Read(buf[:])

		// Send Start-Ok
		_, _ = clientA.Write(buildConnectionStartOk("user", "pass"))

		// Read Tune
		_, _ = clientA.Read(buf[:])

		// Send Tune-Ok
		tuneOk := buildAMQPFrame(frameMethod, 0, []byte{0x00, 0x0A, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x3C})
		_, _ = clientA.Write(tuneOk)

		// Send Connection.Open with allowed vhost "/prod"
		openPayload := []byte{0x00, 0x0A, 0x00, 0x28, 0x05, '/', 'p', 'r', 'o', 'd', 0x00, 0x00}
		openFrame := buildAMQPFrame(frameMethod, 0, openPayload)
		_, _ = clientA.Write(openFrame)

		// Read Connection.Open-Ok
		_, _ = clientA.Read(buf[:])

		// Post-handshake: test bidirectional proxy
		_, _ = clientA.Write([]byte("PING"))
		resp := make([]byte, 4)
		_, _ = io.ReadFull(clientA, resp)
		_ = clientA.Close()
	}()

	select {
	case res := <-done:
		if res.blocked {
			t.Errorf("expected connection to be allowed, got blocked=true")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("test timed out")
	}
}

func TestAMQP_ExtractVHost(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected string
	}{
		{
			name:     "truncated payload",
			payload:  []byte{0x00, 0x0A, 0x00, 0x28},
			expected: "/",
		},
		{
			name:     "empty vhost length returns root slash",
			payload:  []byte{0x00, 0x0A, 0x00, 0x28, 0x00},
			expected: "/",
		},
		{
			name:     "vhost length exceeds payload bounds",
			payload:  []byte{0x00, 0x0A, 0x00, 0x28, 0x10, 'a', 'b'},
			expected: "/",
		},
		{
			name:     "valid custom vhost",
			payload:  []byte{0x00, 0x0A, 0x00, 0x28, 0x04, '/', 'd', 'e', 'v'},
			expected: "/dev",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractVHost(tc.payload)
			if got != tc.expected {
				t.Errorf("extractVHost() = %q; want %q", got, tc.expected)
			}
		})
	}
}
