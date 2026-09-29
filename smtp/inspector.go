package smtp

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

// Inspector inspects SMTP mail transfer sessions.
type Inspector struct {
	MaxRecipients        int
	BlockedSenderDomains []string
	RequireSTARTTLS      bool
}

// Run executes the SMTP inspection and proxying loop.
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

	writeClient := func(s string) error {
		b := []byte(s)
		bytesOut.Add(int64(len(b)))
		_, err := client.Write(b)
		return err
	}

	writeUpstream := func(s string) error {
		_, err := upstream.Write([]byte(s))
		return err
	}

	clientReader := bufio.NewReader(client)
	upstreamReader := bufio.NewReader(upstream)

	greeting, err := readSMTPResponse(upstreamReader)
	if err != nil {
		return result(err), true, "failed reading upstream greeting: " + err.Error(), err
	}
	if err := writeClient(greeting); err != nil {
		return result(err), false, "", err
	}

	inAuthExchange := false

	for {
		client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		clientLine, err := clientReader.ReadString('\n')
		if err != nil {
			return result(nil), false, "", nil
		}
		bytesIn.Add(int64(len(clientLine)))

		trimmed := strings.TrimSpace(clientLine)
		upper := strings.ToUpper(trimmed)

		// 1. DATA Handover
		if upper == "DATA" {
			if err := writeUpstream(clientLine); err != nil {
				return result(err), false, "", err
			}
			resp, err := readSMTPResponse(upstreamReader)
			if err != nil {
				return result(err), false, "", err
			}
			if err := writeClient(resp); err != nil {
				return result(err), false, "", err
			}
			if strings.HasPrefix(strings.TrimSpace(resp), "354") {
				for {
					line, err := clientReader.ReadString('\n')
					if err != nil {
						return result(err), false, "", err
					}
					bytesIn.Add(int64(len(line)))
					if err := writeUpstream(line); err != nil {
						return result(err), false, "", err
					}
					if line == ".\r\n" || line == ".\n" {
						break
					}
				}
				dataResp, err := readSMTPResponse(upstreamReader)
				if err != nil {
					return result(err), false, "", err
				}
				if err := writeClient(dataResp); err != nil {
					return result(err), false, "", err
				}
			}
			continue
		}

		// 2. STARTTLS Handover
		if upper == "STARTTLS" {
			if err := writeUpstream(clientLine); err != nil {
				return result(err), false, "", err
			}
			resp, err := readSMTPResponse(upstreamReader)
			if err != nil {
				return result(err), false, "", err
			}
			if err := writeClient(resp); err != nil {
				return result(err), false, "", err
			}
			if strings.HasPrefix(strings.TrimSpace(resp), "220") {
				clientBuffered := &protocol.BufferedConn{Reader: clientReader, Conn: client}
				upstreamBuffered := &protocol.BufferedConn{Reader: upstreamReader, Conn: upstream}
				res := protocol.Proxy(clientBuffered, upstreamBuffered)
				bytesIn.Add(res.BytesIn)
				bytesOut.Add(res.BytesOut)
				return result(res.Err), false, "", res.Err
			}
			continue
		}

		// 3. Sender domain check
		if strings.HasPrefix(upper, "MAIL FROM:") {
			senderDomain := extractSenderDomain(trimmed[10:])
			if insp.isDomainBlocked(senderDomain) {
				_ = writeClient("554 5.7.1 Sender domain rejected by RouteWarden\r\n")
				return result(nil), true, fmt.Sprintf("blocked sender domain: %s", senderDomain), nil
			}
		}

		// 4. AUTH command tracking
		if strings.HasPrefix(upper, "AUTH ") {
			inAuthExchange = true
		}

		// Forward command to upstream
		if err := writeUpstream(clientLine); err != nil {
			return result(err), false, "", err
		}

		resp, err := readSMTPResponse(upstreamReader)
		if err != nil {
			return result(nil), false, "", nil
		}

		// Check auth result
		if inAuthExchange {
			respTrimmed := strings.TrimSpace(resp)
			if strings.HasPrefix(respTrimmed, "535") || strings.HasPrefix(respTrimmed, "504") || strings.HasPrefix(respTrimmed, "501") {
				if ctx != nil {
					ctx.OnAuthFailure()
				}
				inAuthExchange = false
			} else if strings.HasPrefix(respTrimmed, "235") {
				inAuthExchange = false
			} else if !strings.HasPrefix(respTrimmed, "334") {
				inAuthExchange = false
			}
		}

		if err := writeClient(resp); err != nil {
			return result(err), false, "", err
		}

		if upper == "QUIT" {
			return result(nil), false, "", nil
		}
	}
}

func (insp *Inspector) isDomainBlocked(domain string) bool {
	if domain == "" {
		return false
	}
	domain = strings.ToLower(domain)
	for _, pattern := range insp.BlockedSenderDomains {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if pattern == domain {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			base := strings.TrimPrefix(pattern, "*.")
			if domain == base || strings.HasSuffix(domain, "."+base) {
				return true
			}
		}
		if matched, _ := filepath.Match(pattern, domain); matched {
			return true
		}
	}
	return false
}

func extractSenderDomain(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "<")
	if idx := strings.Index(addr, ">"); idx != -1 {
		addr = addr[:idx]
	}
	if idx := strings.LastIndex(addr, "@"); idx != -1 {
		return strings.ToLower(strings.TrimSpace(addr[idx+1:]))
	}
	return ""
}

func readSMTPResponse(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if sb.Len() > 0 && err == io.EOF {
				sb.WriteString(line)
				return sb.String(), nil
			}
			return sb.String(), err
		}
		sb.WriteString(line)
		trimmed := strings.TrimRight(line, "\r\n")
		if len(trimmed) >= 4 && (trimmed[3] == ' ' || len(trimmed) == 3) {
			break
		}
		if len(trimmed) < 4 {
			break
		}
	}
	return sb.String(), nil
}
