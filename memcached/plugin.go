package memcached

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/routewarden/tcp-warden/plugins"
	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

func init() {
	plugins.Register(&Plugin{})
}

// defaultBlockedCommands are dangerous Memcached commands blocked by default.
var defaultBlockedCommands = []string{"flush_all", "shutdown"}

// Plugin implements sdk.Plugin for Memcached ASCII protocol inspection.
type Plugin struct{}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "memcached",
		Version:     "1.0.0",
		Description: "Memcached ASCII protocol inspector with dangerous command blocking (flush_all, shutdown, etc.)",
		Author:      "RouteWarden Team",
		Protocols:   []string{"memcached"},
	}
}

func (p *Plugin) ValidateConfig(config map[string]any) error {
	if config == nil {
		return nil
	}
	if v, exists := config["blocked_commands"]; exists {
		switch items := v.(type) {
		case []string:
		case []any:
			for _, item := range items {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("blocked_commands must contain strings, got %T", item)
				}
			}
		default:
			return fmt.Errorf("blocked_commands must be a list of strings, got %T", items)
		}
	}
	return nil
}

func (p *Plugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	insp := &Inspector{
		BlockedCommands: defaultBlockedCommands,
	}
	if config != nil {
		if v, ok := config["blocked_commands"]; ok {
			var cmds []string
			switch items := v.(type) {
			case []string:
				cmds = items
			case []any:
				for _, item := range items {
					if s, ok := item.(string); ok {
						cmds = append(cmds, strings.ToLower(s))
					}
				}
			}
			if len(cmds) > 0 {
				insp.BlockedCommands = cmds
			}
		}
	}
	insp.buildLookup()
	return insp, nil
}

// SelfTest verifies flush_all is blocked and connection proceeds normally for safe commands.
func (p *Plugin) SelfTest() error {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	upA, upB := net.Pipe()
	defer upA.Close()
	defer upB.Close()

	var blocked bool
	var mu sync.Mutex

	ctx := &sdk.DefaultContext{
		ServiceName:   "selftest-memcached",
		ClientAddress: "127.0.0.1",
		SecurityFunc: func(action, reason string) {
			if action == "blocked" {
				mu.Lock()
				blocked = true
				mu.Unlock()
			}
		},
	}

	insp := &Inspector{BlockedCommands: []string{"flush_all"}}
	insp.buildLookup()
	done := make(chan error, 1)

	go func() {
		_, wasBlocked, _, err := insp.Run(ctx, clientB, upA)
		if !wasBlocked {
			err = errors.New("self-test failed: flush_all was not blocked")
		}
		done <- err
	}()

	// Synthetic client sends "flush_all" command
	go func() {
		_ = clientA.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Write([]byte("flush_all\r\n"))
		var buf [64]byte
		_ = clientA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientA.Read(buf[:])
	}()

	// Upstream goroutine (should not receive flush_all, but drain anyway)
	go func() {
		var buf [64]byte
		_ = upB.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = upB.Read(buf[:])
	}()

	select {
	case err := <-done:
		if err != nil {
			return err
		}
		mu.Lock()
		b := blocked
		mu.Unlock()
		if !b {
			return errors.New("self-test failed: security event was not triggered")
		}
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("self-test timed out after 3s")
	}
}

// Inspector inspects Memcached ASCII protocol commands.
type Inspector struct {
	BlockedCommands []string
	blockedMap      map[string]struct{}
}

func (insp *Inspector) buildLookup() {
	insp.blockedMap = make(map[string]struct{})
	for _, cmd := range insp.BlockedCommands {
		insp.blockedMap[strings.ToLower(strings.TrimSpace(cmd))] = struct{}{}
	}
}

// Run processes Memcached ASCII commands, blocking dangerous ones and proxying the rest.
func (insp *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	var bytesIn, bytesOut atomic.Int64

	result := func(err error) sdk.ProxyResult {
		return sdk.ProxyResult{BytesIn: bytesIn.Load(), BytesOut: bytesOut.Load(), Err: err}
	}

	if insp.blockedMap == nil {
		insp.buildLookup()
	}

	clientReader := bufio.NewReader(client)
	upstreamReader := bufio.NewReader(upstream)

	for {
		client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		line, err := clientReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return result(nil), false, "", nil
			}
			return result(err), false, "", nil
		}
		bytesIn.Add(int64(len(line)))

		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			// Forward blank lines
			upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := upstream.Write([]byte(line)); err != nil {
				return result(err), false, "", nil
			}
			continue
		}

		// Extract command name (first token)
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		cmd := strings.ToLower(fields[0])

		// Check if blocked
		if _, isBlocked := insp.blockedMap[cmd]; isBlocked {
			errMsg := fmt.Sprintf("ERROR command '%s' blocked by RouteWarden\r\n", strings.ToUpper(cmd))
			client.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, _ = client.Write([]byte(errMsg))
			bytesOut.Add(int64(len(errMsg)))
			if ctx != nil {
				ctx.OnSecurityEvent("blocked", "blocked_memcached_command_"+cmd)
			}
			return result(nil), true, "blocked memcached command: " + cmd, nil
		}

		// Storage commands include a data block after the command line
		var extraData []byte
		if isStorageCommand(cmd) {
			// Format: <cmd> <key> <flags> <exptime> <bytes> [noreply]\r\n<data>\r\n
			if len(fields) >= 5 {
				dataLen := 0
				fmt.Sscanf(fields[4], "%d", &dataLen)
				if dataLen > 0 && dataLen <= 1024*1024 { // max 1MB value
					dataBuf := make([]byte, dataLen+2) // +2 for \r\n
					if _, err := io.ReadFull(clientReader, dataBuf); err != nil {
						return result(err), false, "", nil
					}
					bytesIn.Add(int64(len(dataBuf)))
					extraData = dataBuf
				}
			}
		}

		// Forward command to upstream
		upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := upstream.Write([]byte(line)); err != nil {
			return result(err), false, "", nil
		}
		if len(extraData) > 0 {
			if _, err := upstream.Write(extraData); err != nil {
				return result(err), false, "", nil
			}
		}

		// For "quit", terminate cleanly
		if cmd == "quit" {
			client.SetDeadline(time.Time{})
			upstream.SetDeadline(time.Time{})
			res := protocol.Proxy(client, upstream)
			bytesIn.Add(res.BytesIn)
			bytesOut.Add(res.BytesOut)
			return result(nil), false, "", nil
		}

		// Read upstream response line
		upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
		respLine, err := upstreamReader.ReadString('\n')
		if err != nil {
			return result(err), false, "", nil
		}
		bytesOut.Add(int64(len(respLine)))

		// If response is VALUE, read the data block too
		var respExtra []byte
		if strings.HasPrefix(respLine, "VALUE ") {
			// VALUE <key> <flags> <bytes>\r\n<data>\r\n
			parts := strings.Fields(respLine)
			if len(parts) >= 4 {
				dataLen := 0
				fmt.Sscanf(parts[3], "%d", &dataLen)
				if dataLen > 0 && dataLen <= 1024*1024 {
					dataBuf := make([]byte, dataLen+2)
					if _, err := io.ReadFull(upstreamReader, dataBuf); err != nil {
						return result(err), false, "", nil
					}
					bytesOut.Add(int64(len(dataBuf)))
					respExtra = dataBuf
					// Also read "END\r\n"
					endLine, _ := upstreamReader.ReadString('\n')
					bytesOut.Add(int64(len(endLine)))
					respExtra = append(respExtra, []byte(endLine)...)
				}
			}
		}

		// Forward response to client
		client.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := client.Write([]byte(respLine)); err != nil {
			return result(err), false, "", nil
		}
		if len(respExtra) > 0 {
			if _, err := client.Write(respExtra); err != nil {
				return result(err), false, "", nil
			}
		}
	}
}

func isStorageCommand(cmd string) bool {
	switch cmd {
	case "set", "add", "replace", "append", "prepend", "cas":
		return true
	}
	return false
}
