package mongodb

import (
	"net"
	"testing"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

func TestMongoDB_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest() failed: %v", err)
	}
}

func TestMongoDB_BlockedOp(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	_ = upB // upstream not used for blocked ops test

	insp := &Inspector{BlockedOps: []string{"drop"}}
	ctx := &sdk.DefaultContext{ServiceName: "test", ClientAddress: "127.0.0.1"}

	done := make(chan struct{ blocked bool; reason string }, 1)
	go func() {
		_, blocked, reason, _ := insp.Run(ctx, clientB, upA)
		done <- struct{ blocked bool; reason string }{blocked, reason}
	}()

	// Send OP_MSG with command "drop"
	msg := buildOpMsg(map[string]any{"drop": "mycollection", "$db": "test"})
	_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = clientA.Write(msg)

	select {
	case res := <-done:
		if !res.blocked {
			t.Error("expected 'drop' command to be blocked")
		}
	case <-time.After(3 * time.Second):
		t.Error("test timed out")
	}
}
