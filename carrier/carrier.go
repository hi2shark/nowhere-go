// Package carrier defines transport-facing interfaces for Nowhere outbound.
// Hosts inject Logger, TCP/TLS dialers, and QuicBackend; core imports neither host.
package carrier

import (
	"context"
	"net"
)

// Carrier opens TCP or UDP flows on one transport direction.
type Carrier interface {
	OpenTCP(ctx context.Context, dest string) (net.Conn, error)
	OpenUDP(ctx context.Context, dest string) (net.PacketConn, error)
	Close() error
}
