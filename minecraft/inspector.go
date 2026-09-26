package minecraft

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

// Inspector inspects Minecraft Java Edition handshake packets.
type Inspector struct {
	BlockedProtocolVersions []int
}

// Run inspects initial Minecraft handshake packet and switches to proxy mode.
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

	client.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Peek up to 512 bytes of the handshake
	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil && err != io.EOF {
		return result(err), false, "", err
	}
	bytesIn.Add(int64(n))

	if n < 3 {
		return result(nil), true, "minecraft handshake packet too short", nil
	}

	// Forward handshake to upstream
	upstream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if n > 0 {
		if _, err := upstream.Write(buf[:n]); err != nil {
			return result(err), false, "", err
		}
		bytesOut.Add(int64(n))
	}

	client.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})

	bufferedClient := &protocol.BufferedConn{
		Reader: bytes.NewReader(nil),
		Conn:   client,
	}

	proxyRes := protocol.Proxy(bufferedClient, upstream)
	bytesIn.Add(proxyRes.BytesIn)
	bytesOut.Add(proxyRes.BytesOut)

	if ctx != nil {
		ctx.OnSecurityEvent("allowed", fmt.Sprintf("minecraft_session_%d_bytes", bytesIn.Load()))
	}

	return result(proxyRes.Err), false, "", nil
}
