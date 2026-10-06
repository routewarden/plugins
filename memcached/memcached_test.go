package memcached

import (
	"io"
	"net"
	"strings"
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

func TestMemcached_ShutdownBlocked(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{BlockedCommands: []string{"flush_all", "shutdown"}}
	insp.buildLookup()

	done := make(chan bool, 1)
	go func() {
		_, blocked, _, _ := insp.Run(nil, clientB, upA)
		done <- blocked
	}()

	_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = clientA.Write([]byte("shutdown\r\n"))

	var buf [128]byte
	_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := clientA.Read(buf[:])
	resp := string(buf[:n])
	if !strings.Contains(resp, "ERROR command 'SHUTDOWN' blocked") {
		t.Errorf("expected blocked error message, got: %s", resp)
	}

	select {
	case b := <-done:
		if !b {
			t.Errorf("expected shutdown to be blocked")
		}
	case <-time.After(3 * time.Second):
		t.Error("test timed out")
	}
}

func TestMemcached_GetCommandForwarding(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{BlockedCommands: []string{"flush_all"}}
	insp.buildLookup()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _, _ = insp.Run(nil, clientB, upA)
	}()

	// Client sends get mykey\r\n
	go func() {
		_, _ = clientA.Write([]byte("get mykey\r\n"))
	}()

	// Upstream receives get mykey\r\n
	var upBuf [64]byte
	n, err := upB.Read(upBuf[:])
	if err != nil {
		t.Fatalf("upstream failed read: %v", err)
	}
	if string(upBuf[:n]) != "get mykey\r\n" {
		t.Errorf("upstream received %q, expected 'get mykey\\r\\n'", string(upBuf[:n]))
	}

	// Upstream responds with VALUE block and END
	upstreamResp := "VALUE mykey 0 5\r\nhello\r\nEND\r\n"
	go func() {
		_, _ = upB.Write([]byte(upstreamResp))
	}()

	// Client receives the full response (two writes: header line + data/END)
	clientBuf := make([]byte, len(upstreamResp))
	if _, err := io.ReadFull(clientA, clientBuf); err != nil {
		t.Fatalf("client failed reading full response: %v", err)
	}
	if string(clientBuf) != upstreamResp {
		t.Errorf("client received %q, expected %q", string(clientBuf), upstreamResp)
	}

	_ = clientA.Close()
	_ = upB.Close()
	<-done
}

func TestMemcached_SetCommandForwarding(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{BlockedCommands: []string{"flush_all"}}
	insp.buildLookup()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _, _ = insp.Run(nil, clientB, upA)
	}()

	// Client sends set command with payload: set mykey 0 0 5\r\nhello\r\n
	clientPayload := "set mykey 0 0 5\r\nhello\r\n"
	go func() {
		_, _ = clientA.Write([]byte(clientPayload))
	}()

	// Upstream receives command line and data (two writes from inspector)
	upBuf := make([]byte, len(clientPayload))
	if _, err := io.ReadFull(upB, upBuf); err != nil {
		t.Fatalf("upstream failed reading full payload: %v", err)
	}
	if string(upBuf) != clientPayload {
		t.Errorf("upstream received %q, expected %q", string(upBuf), clientPayload)
	}

	// Upstream responds STORED\r\n
	go func() {
		_, _ = upB.Write([]byte("STORED\r\n"))
	}()

	// Client reads STORED\r\n
	var clientBuf [64]byte
	clientN, err := clientA.Read(clientBuf[:])
	if err != nil {
		t.Fatalf("client failed read: %v", err)
	}
	if string(clientBuf[:clientN]) != "STORED\r\n" {
		t.Errorf("client received %q, expected 'STORED\\r\\n'", string(clientBuf[:clientN]))
	}

	_ = clientA.Close()
	_ = upB.Close()
	<-done
}

func TestMemcached_ValidateConfig(t *testing.T) {
	p := &Plugin{}
	if err := p.ValidateConfig(nil); err != nil {
		t.Errorf("nil config rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"blocked_commands": []string{"flush_all"}}); err != nil {
		t.Errorf("valid string slice rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"blocked_commands": []any{"flush_all", "shutdown"}}); err != nil {
		t.Errorf("valid any slice rejected: %v", err)
	}
	if err := p.ValidateConfig(map[string]any{"blocked_commands": "not-a-slice"}); err == nil {
		t.Errorf("expected error for non-slice blocked_commands")
	}
	if err := p.ValidateConfig(map[string]any{"blocked_commands": []any{123}}); err == nil {
		t.Errorf("expected error for non-string elements in blocked_commands")
	}
}

func TestMemcached_SetEmptyValueForwarding(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{BlockedCommands: []string{"flush_all"}}
	insp.buildLookup()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _, _ = insp.Run(nil, clientB, upA)
	}()

	// Client sends set command with 0-byte payload: set emptykey 0 0 0\r\n\r\n
	clientPayload := "set emptykey 0 0 0\r\n\r\n"
	go func() {
		_, _ = clientA.Write([]byte(clientPayload))
	}()

	// Upstream receives command line and empty data (the 2-byte \r\n)
	upBuf := make([]byte, len(clientPayload))
	if _, err := io.ReadFull(upB, upBuf); err != nil {
		t.Fatalf("upstream failed reading empty payload: %v", err)
	}
	if string(upBuf) != clientPayload {
		t.Errorf("upstream received %q, expected %q", string(upBuf), clientPayload)
	}

	// Upstream responds STORED\r\n
	go func() {
		_, _ = upB.Write([]byte("STORED\r\n"))
	}()

	var clientBuf [64]byte
	clientN, err := clientA.Read(clientBuf[:])
	if err != nil {
		t.Fatalf("client failed read: %v", err)
	}
	if string(clientBuf[:clientN]) != "STORED\r\n" {
		t.Errorf("client received %q, expected 'STORED\\r\\n'", string(clientBuf[:clientN]))
	}

	_ = clientA.Close()
	_ = upB.Close()
	<-done
}

func TestMemcached_NoReplyHandling(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	insp := &Inspector{BlockedCommands: []string{"flush_all"}}
	insp.buildLookup()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _, _ = insp.Run(nil, clientB, upA)
	}()

	// Client sends set with noreply, followed immediately by get command
	setPayload := "set mykey 0 0 5 noreply\r\nhello\r\n"
	getPayload := "get mykey\r\n"
	go func() {
		_, _ = clientA.Write([]byte(setPayload + getPayload))
	}()

	// Upstream receives set payload
	upBufSet := make([]byte, len(setPayload))
	if _, err := io.ReadFull(upB, upBufSet); err != nil {
		t.Fatalf("upstream failed reading set payload: %v", err)
	}
	if string(upBufSet) != setPayload {
		t.Errorf("upstream received %q, expected %q", string(upBufSet), setPayload)
	}

	// Upstream does NOT reply to set (noreply), but receives getPayload
	upBufGet := make([]byte, len(getPayload))
	if _, err := io.ReadFull(upB, upBufGet); err != nil {
		t.Fatalf("upstream failed reading get payload: %v", err)
	}
	if string(upBufGet) != getPayload {
		t.Errorf("upstream received %q, expected %q", string(upBufGet), getPayload)
	}

	// Upstream replies to get
	go func() {
		_, _ = upB.Write([]byte("VALUE mykey 0 5\r\nhello\r\nEND\r\n"))
	}()

	expectedResp := "VALUE mykey 0 5\r\nhello\r\nEND\r\n"
	clientBuf := make([]byte, len(expectedResp))
	if _, err := io.ReadFull(clientA, clientBuf); err != nil {
		t.Fatalf("client failed reading response to get: %v", err)
	}
	if string(clientBuf) != expectedResp {
		t.Errorf("client received %q, expected %q", string(clientBuf), expectedResp)
	}

	_ = clientA.Close()
	_ = upB.Close()
	<-done
}

