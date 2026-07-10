// Package quic defines host-injected QUIC interfaces (no QUIC library imports).
package quic

import (
	"context"
	"net"

	"github.com/hi2shark/go-nowhere/wire"
)

// Backend is injected via bundle.BundleConfig.Quic.
type Backend interface {
	SetSessionID(id wire.SessionID)
	OpenTCP(ctx context.Context, dest string) (net.Conn, error)
	OpenFlowStream(ctx context.Context, dest string, header wire.FlowHeader) (net.Conn, error)
	OpenUDP(ctx context.Context, dest string) (net.PacketConn, error)
	AcquireSession(ctx context.Context) (Session, error)
	InvalidateSession(session Session)
	Close()
}
