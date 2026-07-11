// Package quic defines host-injected QUIC interfaces (no QUIC library imports).
package quic

import (
	"context"
	"net"

	"github.com/hi2shark/nowhere-go/wire"
)

// PreparedFlowStream is an opened QUIC stream that has not yet written a FLOW frame.
// Exactly one of Commit or Close must run; both are idempotent via host Once.
type PreparedFlowStream interface {
	Commit(ctx context.Context, dest string, header wire.FlowHeader) (net.Conn, error)
	Close() error
}

// Backend is injected via bundle.BundleOptions.QUIC.
type Backend interface {
	SetSessionID(id wire.SessionID)
	OpenTCP(ctx context.Context, dest string) (net.Conn, error)
	OpenFlowStream(ctx context.Context, dest string, header wire.FlowHeader) (net.Conn, error)
	// PrepareFlowStream opens a bidirectional stream without writing FLOW/request bytes.
	PrepareFlowStream(ctx context.Context) (PreparedFlowStream, error)
	OpenUDP(ctx context.Context, dest string) (net.PacketConn, error)
	AcquireSession(ctx context.Context) (Session, error)
	InvalidateSession(session Session)
	Close()
}
