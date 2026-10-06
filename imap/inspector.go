package imap

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

// Inspector inspects IMAP mail sessions.
type Inspector struct {
	MaxAuthFailures int
}

var errLineTooLong = errors.New("imap: line too long")

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

// Run executes the IMAP inspection and relay loop.
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
		return result(err), true, "failed reading IMAP greeting: " + err.Error(), err
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
				_, _ = client.Write([]byte("* BAD Line too long\r\n"))
			}
			return result(nil), false, "", nil
		}
		bytesIn.Add(int64(len(clientLine)))

		parts := strings.Fields(strings.TrimSpace(clientLine))
		tag := ""
		cmd := ""
		if len(parts) >= 2 {
			tag = parts[0]
			cmd = strings.ToUpper(parts[1])
		}

		// STARTTLS Handover
		if cmd == "STARTTLS" {
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
			if strings.Contains(strings.ToUpper(resp), "OK") {
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

		// Read responses until tagged completion response
		for {
			resp, err := readBoundedLine(upstreamReader, 65536)
			if err != nil {
				return result(nil), false, "", nil
			}
			bytesOut.Add(int64(len(resp)))
			if _, err := client.Write([]byte(resp)); err != nil {
				return result(err), false, "", err
			}

			trimmedResp := strings.TrimSpace(resp)
			respParts := strings.Fields(trimmedResp)

			if tag != "" && len(respParts) >= 2 && respParts[0] == tag {
				status := strings.ToUpper(respParts[1])
				if (cmd == "LOGIN" || cmd == "AUTHENTICATE") && (status == "NO" || status == "BAD") {
					authFailures++
					if ctx != nil {
						ctx.OnAuthFailure()
					}
					if insp.MaxAuthFailures > 0 && authFailures >= insp.MaxAuthFailures {
						byeMsg := "* BYE Too many authentication failures\r\n"
						_, _ = client.Write([]byte(byeMsg))
						bytesOut.Add(int64(len(byeMsg)))
						if ctx != nil {
							ctx.OnSecurityEvent("blocked", "imap_max_auth_failures_exceeded")
						}
						return result(nil), true, fmt.Sprintf("max auth failures exceeded (%d)", authFailures), nil
					}
				} else if (cmd == "LOGIN" || cmd == "AUTHENTICATE") && status == "OK" {
					authFailures = 0
				}
				break
			}

			// Continuation or untagged response continues
			if tag == "" || (!strings.HasPrefix(trimmedResp, "*") && !strings.HasPrefix(trimmedResp, "+")) {
				break
			}
		}

		if cmd == "LOGOUT" {
			return result(nil), false, "", nil
		}
	}
}
