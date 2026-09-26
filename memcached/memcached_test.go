package memcached

import (
	"net"
	"testing"
	"time"
)

func TestMemcached_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest() failed: %v", err)
	}
}

func TestMemcached_FlushAllBlocked(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	_ = upB

	insp := &Inspector{BlockedCommands: []string{"flush_all", "shutdown"}}
	insp.buildLookup()

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

	_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = clientA.Write([]byte("flush_all\r\n"))

	// Read the error response
	var buf [64]byte
	_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
	clientA.Read(buf[:])

	select {
	case res := <-done:
		if !res.blocked {
			t.Errorf("expected flush_all to be blocked, got reason=%q", res.reason)
		}
	case <-time.After(3 * time.Second):
		t.Error("test timed out")
	}
}
