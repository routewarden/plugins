package mongodb

import (
	"io"
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

	// Drain upB in the background so pipe writes never deadlock if inspection fails
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := upB.Read(buf); err != nil {
				return
			}
		}
	}()

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

func TestMongoDB_AllowedOpForwarded(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{BlockedOps: []string{"drop"}}
	insp.buildLookup()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, blocked, reason, _ := insp.Run(nil, clientB, upA)
		if blocked {
			t.Errorf("expected allowed op, got blocked: %s", reason)
		}
	}()

	// Send OP_MSG with allowed command "find"
	reqMsg := buildOpMsg(map[string]any{"find": "users", "$db": "test"})
	go func() {
		_, _ = clientA.Write(reqMsg)
	}()

	// Upstream reads OP_MSG
	upBuf := make([]byte, len(reqMsg))
	if _, err := io.ReadFull(upB, upBuf); err != nil {
		t.Fatalf("upstream failed reading request: %v", err)
	}

	// Upstream responds with ok: 1
	replyMsg := buildOpMsg(map[string]any{"ok": int32(1)})
	go func() {
		_, _ = upB.Write(replyMsg)
	}()

	// Client receives response
	clientBuf := make([]byte, len(replyMsg))
	if _, err := io.ReadFull(clientA, clientBuf); err != nil {
		t.Fatalf("client failed reading response: %v", err)
	}

	_ = clientA.Close()
	_ = upB.Close()
	<-done
}

func TestMongoDB_AuthFailure(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	authFailed := false
	ctx := &sdk.DefaultContext{
		ServiceName:   "mongo-test",
		ClientAddress: "127.0.0.1",
		AuthFailureFunc: func() {
			authFailed = true
		},
	}

	insp := &Inspector{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _, _ = insp.Run(ctx, clientB, upA)
	}()

	// Client sends auth request
	reqMsg := buildOpMsg(map[string]any{"authenticate": 1})
	go func() {
		_, _ = clientA.Write(reqMsg)
	}()

	// Upstream drains request and replies with code 18 (Auth failed)
	upBuf := make([]byte, len(reqMsg))
	_, _ = io.ReadFull(upB, upBuf)

	replyMsg := buildOpMsg(map[string]any{
		"ok":     int32(0),
		"code":   int32(18),
		"errmsg": "auth failed",
	})
	go func() {
		_, _ = upB.Write(replyMsg)
	}()

	// Client drains response
	clientBuf := make([]byte, len(replyMsg))
	_, _ = io.ReadFull(clientA, clientBuf)

	_ = clientA.Close()
	_ = upB.Close()
	<-done

	if !authFailed {
		t.Errorf("expected AuthFailureFunc to be called on code 18 response")
	}
}

func TestMongoDB_ValidateConfig(t *testing.T) {
	p := &Plugin{}
	if err := p.ValidateConfig(nil); err != nil {
		t.Errorf("nil config rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"max_auth_failures": 5, "blocked_ops": []string{"drop"}}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"max_auth_failures": "not-an-int"}); err == nil {
		t.Errorf("expected error for non-int max_auth_failures")
	}
	if err := p.ValidateConfig(map[string]any{"blocked_ops": 123}); err == nil {
		t.Errorf("expected error for non-slice blocked_ops")
	}
	if err := p.ValidateConfig(map[string]any{"blocked_ops": []any{999}}); err == nil {
		t.Errorf("expected error for non-string elements in blocked_ops")
	}
}
