// Package quic defines host-injected QUIC interfaces (no QUIC library imports).
package quic

import (
	"context"
	"net"

	"github.com/hi2shark/nowhere-go/wire"
)

// PreparedStream is an opened QUIC stream that has not yet written setup bytes.
// Exactly one of Commit or Close must run; both are idempotent via host Once.
type PreparedStream interface {
	// Commit writes opaque setup bytes, optionally finishes the write side, and returns the resulting net.Conn.
	Commit(ctx context.Context, setup []byte, finishWrite bool) (net.Conn, error)
	Close() error
}

// Backend is injected via bundle.BundleOptions.QUIC.
type Backend interface {
	SetSessionID(id wire.SessionID)
	AcquireSession(ctx context.Context) (Session, error)
	InvalidateSession(session Session)
	Close() error
}

// Session is one authenticated QUIC connection.
type Session interface {
	PrepareStream(ctx context.Context) (PreparedStream, error)
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	CurrentMaxDatagramSize() int
	SendDatagram([]byte) error
	LocalAddr() net.Addr
}
