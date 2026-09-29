package imap

import (
	"bufio"
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

	greeting, err := upstreamReader.ReadString('\n')
	if err != nil {
		return result(err), true, "failed reading IMAP greeting: " + err.Error(), err
	}
	bytesOut.Add(int64(len(greeting)))
	if _, err := client.Write([]byte(greeting)); err != nil {
		return result(err), false, "", err
	}

	for {
		client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		clientLine, err := clientReader.ReadString('\n')
		if err != nil {
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
			resp, err := upstreamReader.ReadString('\n')
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
			resp, err := upstreamReader.ReadString('\n')
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
					if ctx != nil {
						ctx.OnAuthFailure()
					}
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
