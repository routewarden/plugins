package ssh

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

// Inspector inspects SSH client handshakes and watches upstream for auth failures.
type Inspector struct {
	Banner       string
	MaxAuthTries int
}

// Run executes the SSH inspection and proxying loop.
func (insp *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	// 1. Inspect client banner
	br, res := inspectSSHBanner(client)
	if !res.Valid {
		rejectSSH(client, "invalid SSH client protocol banner")
		return sdk.ProxyResult{}, true, "invalid SSH protocol banner: " + res.ClientVersion, errors.New("invalid SSH protocol banner")
	}

	if res.IsSSH1 {
		rejectSSH1(client)
		return sdk.ProxyResult{}, true, "SSH-1.x rejected", errors.New("SSH-1.x rejected")
	}

	// 2. Wrap upstream to detect SSH_MSG_USERAUTH_FAILURE (type 51)
	monitor := newSSHAuthMonitor(func() {
		if ctx != nil {
			ctx.OnAuthFailure()
		}
	})
	monitoredUpstream := monitor.WrapUpstream(upstream)

	// 3. Wrap client connection to preserve peeked banner bytes
	bufferedClient := &protocol.BufferedConn{
		Reader: br,
		Conn:   client,
	}

	// 4. Proxy session
	proxyRes := protocol.Proxy(bufferedClient, monitoredUpstream)

	return sdk.ProxyResult{
		BytesIn:  proxyRes.BytesIn,
		BytesOut: proxyRes.BytesOut,
		Err:      proxyRes.Err,
	}, false, "", proxyRes.Err
}

type sshResult struct {
	ClientVersion string
	IsSSH1        bool
	Valid         bool
}

func inspectSSHBanner(conn net.Conn) (*bufio.Reader, sshResult) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return br, sshResult{}
	}
	line = strings.TrimSpace(line)

	result := sshResult{
		ClientVersion: line,
		Valid:         strings.HasPrefix(line, "SSH-"),
	}
	if strings.HasPrefix(line, "SSH-1.") {
		result.IsSSH1 = true
	}
	return br, result
}

type sshAuthMonitor struct {
	AuthFailures int
	onFailure    func()
}

func newSSHAuthMonitor(onFailure func()) *sshAuthMonitor {
	return &sshAuthMonitor{onFailure: onFailure}
}

func (m *sshAuthMonitor) WrapUpstream(upstream net.Conn) net.Conn {
	return &sshMonitorConn{Conn: upstream, monitor: m}
}

type sshMonitorConn struct {
	net.Conn
	monitor *sshAuthMonitor
	buf     []byte
}

func (c *sshMonitorConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.buf = append(c.buf, p[:n]...)
		c.scan()
	}
	return n, err
}

func (c *sshMonitorConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *sshMonitorConn) scan() {
	for len(c.buf) >= 6 {
		pktLen := int(c.buf[0])<<24 | int(c.buf[1])<<16 | int(c.buf[2])<<8 | int(c.buf[3])
		if pktLen < 2 || pktLen > 35000 {
			c.buf = c.buf[1:]
			continue
		}
		total := 4 + pktLen
		if len(c.buf) < total {
			break
		}
		msgType := c.buf[5]

		const sshMsgUserAuthFailure = 51
		if msgType == sshMsgUserAuthFailure {
			c.monitor.AuthFailures++
			if c.monitor.onFailure != nil {
				c.monitor.onFailure()
			}
		}
		c.buf = c.buf[total:]
	}
	if len(c.buf) > 65536 {
		c.buf = c.buf[len(c.buf)-65536:]
	}
}

func rejectSSH1(conn net.Conn) {
	banner := "SSH-2.0-RouteWarden_TCP_Warden\r\n"
	_, _ = conn.Write([]byte(banner))
	msg := buildSSHDisconnect(7, "SSH-1.x not supported")
	_, _ = conn.Write(msg)
	_ = conn.Close()
}

func rejectSSH(conn net.Conn, reason string) {
	_, _ = conn.Write([]byte("SSH-2.0-RouteWarden_TCP_Warden\r\n"))
	msg := buildSSHDisconnect(11, reason)
	_, _ = conn.Write(msg)
	_ = conn.Close()
}

func buildSSHDisconnect(code uint32, message string) []byte {
	msgLen := 1 + 4 + 4 + len(message) + 4
	totalNoPadding := 4 + 1 + msgLen
	rem := totalNoPadding % 8
	padding := 8 - rem
	if padding < 4 {
		padding += 8
	}
	pktLen := 1 + msgLen + padding

	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "%c%c%c%c",
		byte(pktLen>>24), byte(pktLen>>16), byte(pktLen>>8), byte(pktLen))
	buf.WriteByte(byte(padding))
	buf.WriteByte(1) // SSH_MSG_DISCONNECT
	fmt.Fprintf(buf, "%c%c%c%c",
		byte(code>>24), byte(code>>16), byte(code>>8), byte(code))
	mlen := uint32(len(message))
	fmt.Fprintf(buf, "%c%c%c%c", byte(mlen>>24), byte(mlen>>16), byte(mlen>>8), byte(mlen))
	buf.WriteString(message)
	buf.Write([]byte{0, 0, 0, 0})
	buf.Write(make([]byte, padding))

	return buf.Bytes()
}
