// Package quic defines host-injected QUIC interfaces (no QUIC library imports).
//
// The carrier-layer Session represents one QUIC connection that has completed
// its handshake. The nowhere-go core reads the TLS exporter off the Session,
// opens the first stream itself, writes the connection-bound auth frame, and
// then drives subsequent flows. The host never knows the Session ID.
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

// Backend owns the physical QUIC Session lifecycle. It is injected via
// bundle.BundleOptions.QUIC and is owned by exactly one Bundle; it must not
// expose or accept the Session ID.
type Backend interface {
	// AcquireSession returns a ready (handshaked) physical Session. The same
	// physical session may be returned until it is invalidated.
	AcquireSession(ctx context.Context) (Session, error)
	// InvalidateSession drops the supplied physical session; the host must
	// close it and unblock any concurrent Acquire/Prepare/Receive/Send.
	InvalidateSession(session Session)
	Close() error
}

// Session is one QUIC connection whose TLS 1.3 handshake has completed.
type Session interface {
	// TLSExporter returns the keying material exported from this connection's
	// TLS handshake, used to bind the connection-bound auth frame.
	TLSExporter() (wire.TLSExporter, error)
	PrepareStream(ctx context.Context) (PreparedStream, error)
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	CurrentMaxDatagramSize() int
	SendDatagram([]byte) error
	LocalAddr() net.Addr
}
