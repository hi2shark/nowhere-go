package bundle

import (
	"context"
	"net"

	"github.com/hi2shark/nowhere-go/wire"
)

var _ func(*CarrierBundle, context.Context, wire.Target) (net.PacketConn, error) = (*CarrierBundle).OpenUDP
