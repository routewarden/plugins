package generic

import (
	"net"

	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

// Inspector provides transparent Layer 4 TCP proxying.
type Inspector struct{}

// Run executes the generic TCP proxying loop.
func (insp *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	res := protocol.Proxy(client, upstream)
	return sdk.ProxyResult{
		BytesIn:  res.BytesIn,
		BytesOut: res.BytesOut,
		Err:      res.Err,
	}, false, "", res.Err
}
