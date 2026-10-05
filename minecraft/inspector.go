package minecraft

import (
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
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
		if err == io.EOF || errors.Is(err, io.EOF) {
			return result(err), false, "", err
		}
		return result(nil), true, "minecraft handshake packet too short", nil
	}

	// Inspect protocol version if blocked list is configured
	if len(insp.BlockedProtocolVersions) > 0 {
		_, nLen, err := readVarInt(buf[:n])
		if err == nil && nLen < n {
			packetID, nID, err := readVarInt(buf[nLen:n])
			if err == nil && packetID == 0 && nLen+nID < n {
				protoVer, _, err := readVarInt(buf[nLen+nID : n])
				if err == nil {
					if slices.Contains(insp.BlockedProtocolVersions, protoVer) {
							if ctx != nil {
								ctx.OnSecurityEvent("blocked", fmt.Sprintf("minecraft_protocol_version_%d_blocked", protoVer))
							}
							return result(nil), true, fmt.Sprintf("blocked minecraft protocol version: %d", protoVer), nil
						}
				}
			}
		}
	}

	// Forward handshake to upstream
	upstream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if n > 0 {
		if _, err := upstream.Write(buf[:n]); err != nil {
			return result(err), false, "", err
		}
	}

	client.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})

	proxyRes := protocol.Proxy(client, upstream)
	bytesIn.Add(proxyRes.BytesIn)
	bytesOut.Add(proxyRes.BytesOut)

	if ctx != nil {
		ctx.OnSecurityEvent("allowed", fmt.Sprintf("minecraft_session_%d_bytes", bytesIn.Load()))
	}

	return result(proxyRes.Err), false, "", proxyRes.Err
}

func readVarInt(b []byte) (int, int, error) {
	var result uint32
	var numRead int
	for {
		if numRead >= len(b) {
			return 0, 0, io.ErrUnexpectedEOF
		}
		read := b[numRead]
		value := uint32(read & 0x7F)
		result |= (value << (7 * numRead))
		numRead++
		if numRead > 5 {
			return 0, 0, fmt.Errorf("VarInt too big")
		}
		if (read & 0x80) == 0 {
			break
		}
	}
	return int(result), numRead, nil
}
