package bundle

import (
	"context"
	"net"
)

var _ func(*CarrierBundle, context.Context, string) (net.PacketConn, error) = (*CarrierBundle).OpenUDP
