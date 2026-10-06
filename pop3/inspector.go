package pop3

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

// Inspector inspects POP3 mail sessions.
type Inspector struct {
	MaxAuthFailures int
}

var errLineTooLong = errors.New("pop3: line too long")

func readBoundedLine(r *bufio.Reader, maxLen int) (string, error) {
	var buf []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			if len(buf) > 0 && err == io.EOF {
				return string(buf), nil
			}
			return string(buf), err
		}
		buf = append(buf, b)
		if b == '\n' {
			return string(buf), nil
		}
		if len(buf) >= maxLen {
			return string(buf), errLineTooLong
		}
	}
}

// Run executes the POP3 inspection and relay loop.
func (insp *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	var bytesIn atomic.Int64
	var bytesOut atomic.Int64

	result := func(err error) sdk.ProxyResult {
		return sdk.ProxyResult{
			BytesIn:  bytesIn.Load(),
			BytesOut: bytesOut.Load(),
			Err:      err,
		}
	}

	clientReader := bufio.NewReader(client)
	upstreamReader := bufio.NewReader(upstream)

	greeting, err := readBoundedLine(upstreamReader, 8192)
	if err != nil {
		return result(err), true, "failed reading POP3 greeting: " + err.Error(), err
	}
	bytesOut.Add(int64(len(greeting)))
	if _, err := client.Write([]byte(greeting)); err != nil {
		return result(err), false, "", err
	}

	authFailures := 0

	for {
		client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		clientLine, err := readBoundedLine(clientReader, 4096)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				_, _ = client.Write([]byte("-ERR Line too long\r\n"))
			}
			return result(nil), false, "", nil
		}
		bytesIn.Add(int64(len(clientLine)))

		trimmed := strings.TrimSpace(clientLine)
		upper := strings.ToUpper(trimmed)

		// STLS Handover
		if upper == "STLS" {
			if _, err := upstream.Write([]byte(clientLine)); err != nil {
				return result(err), false, "", err
			}
			resp, err := readBoundedLine(upstreamReader, 8192)
			if err != nil {
				return result(err), false, "", err
			}
			bytesOut.Add(int64(len(resp)))
			if _, err := client.Write([]byte(resp)); err != nil {
				return result(err), false, "", err
			}
			if strings.HasPrefix(strings.TrimSpace(resp), "+OK") {
				clientBuffered := &protocol.BufferedConn{Reader: clientReader, Conn: client}
				upstreamBuffered := &protocol.BufferedConn{Reader: upstreamReader, Conn: upstream}
				res := protocol.Proxy(clientBuffered, upstreamBuffered)
				bytesIn.Add(res.BytesIn)
				bytesOut.Add(res.BytesOut)
				return result(res.Err), false, "", res.Err
			}
			continue
		}

		if _, err := upstream.Write([]byte(clientLine)); err != nil {
			return result(err), false, "", err
		}

		// Read response
		isMultiLine := upper == "LIST" || upper == "UIDL" || strings.HasPrefix(upper, "RETR ") || strings.HasPrefix(upper, "TOP ") || upper == "CAPA"
		isSingleArg := strings.HasPrefix(upper, "LIST ") || strings.HasPrefix(upper, "UIDL ")
		if isSingleArg {
			isMultiLine = false
		}

		resp, err := readBoundedLine(upstreamReader, 8192)
		if err != nil {
			return result(nil), false, "", nil
		}
		bytesOut.Add(int64(len(resp)))
		if _, err := client.Write([]byte(resp)); err != nil {
			return result(err), false, "", err
		}

		trimmedResp := strings.TrimSpace(resp)

		// Check auth failure
		if strings.HasPrefix(upper, "PASS ") || strings.HasPrefix(upper, "AUTH ") {
			if strings.HasPrefix(trimmedResp, "-ERR") {
				authFailures++
				if ctx != nil {
					ctx.OnAuthFailure()
				}
				if insp.MaxAuthFailures > 0 && authFailures >= insp.MaxAuthFailures {
					errMsg := "-ERR Too many authentication failures\r\n"
					_, _ = client.Write([]byte(errMsg))
					bytesOut.Add(int64(len(errMsg)))
					if ctx != nil {
						ctx.OnSecurityEvent("blocked", "pop3_max_auth_failures_exceeded")
					}
					return result(nil), true, fmt.Sprintf("max auth failures exceeded (%d)", authFailures), nil
				}
			} else if strings.HasPrefix(trimmedResp, "+OK") {
				authFailures = 0
			}
		}

		// Multi-line data relay (terminated by dot-CRLF)
		if isMultiLine && strings.HasPrefix(trimmedResp, "+OK") {
			for {
				line, err := readBoundedLine(upstreamReader, 65536)
				if err != nil {
					return result(nil), false, "", nil
				}
				bytesOut.Add(int64(len(line)))
				if _, err := client.Write([]byte(line)); err != nil {
					return result(err), false, "", err
				}
				if line == ".\r\n" || line == ".\n" {
					break
				}
			}
		}

		if upper == "QUIT" {
			return result(nil), false, "", nil
		}
	}
}
