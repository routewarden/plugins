package ftp

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFTPPlugin_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("ftp SelfTest failed: %v", err)
	}
}

func TestFTPPlugin_ManifestAndConfig(t *testing.T) {
	p := &Plugin{}
	m := p.Manifest()
	if m.Name != "ftp" {
		t.Errorf("expected ftp, got %s", m.Name)
	}

	if err := p.ValidateConfig(map[string]any{"max_auth_failures": 5}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	insp, err := p.CreateInspector(nil)
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}

func TestFTPPlugin_AuthTLS_BufferedHandover(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	p := &Plugin{}
	insp, err := p.CreateInspector(nil)
	if err != nil {
		t.Fatalf("CreateInspector: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, _, err := insp.Run(nil, clientB, upA)
		done <- err
	}()

	// Upstream server mock
	upErr := make(chan error, 1)
	go func() {
		// Send greeting
		_, _ = upB.Write([]byte("220 FTP Server ready\r\n"))

		// Read AUTH TLS
		buf := make([]byte, 128)
		n, err := upB.Read(buf)
		if err != nil {
			upErr <- err
			return
		}
		if string(buf[:n]) != "AUTH TLS\r\n" {
			upErr <- fmt.Errorf("unexpected command: %q", string(buf[:n]))
			return
		}

		// Reply with 234
		_, _ = upB.Write([]byte("234 Enabling TLS Connection\r\n"))

		// Read pipelined TLS client hello bytes
		expected := "SYNTHETIC_TLS_HELLO"
		tlsBuf := make([]byte, len(expected))
		if _, err := io.ReadFull(upB, tlsBuf); err != nil {
			upErr <- err
			return
		}
		if string(tlsBuf) != expected {
			upErr <- fmt.Errorf("unexpected TLS payload: %q", string(tlsBuf))
			return
		}
		upErr <- nil
	}()

	// Client: read greeting, send AUTH TLS + pipelined TLS payload
	var greetingBuf [64]byte
	n, err := clientA.Read(greetingBuf[:])
	if err != nil {
		t.Fatalf("client read greeting: %v", err)
	}
	if !strings.HasPrefix(string(greetingBuf[:n]), "220") {
		t.Fatalf("unexpected greeting: %s", string(greetingBuf[:n]))
	}

	// Send AUTH TLS and immediate TLS hello bytes
	_, _ = clientA.Write([]byte("AUTH TLS\r\nSYNTHETIC_TLS_HELLO"))

	// Read 234 response
	var respBuf [64]byte
	n, err = clientA.Read(respBuf[:])
	if err != nil {
		t.Fatalf("client read 234: %v", err)
	}
	if !strings.HasPrefix(string(respBuf[:n]), "234") {
		t.Fatalf("unexpected response: %s", string(respBuf[:n]))
	}

	select {
	case err := <-upErr:
		if err != nil {
			t.Fatalf("upstream error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream to receive buffered TLS hello")
	}
}

