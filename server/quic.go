package server

import (
	"context"
	"io"
	"net"
	"time"
)

// QuicStream is one bidirectional QUIC stream.
type QuicStream interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	CancelRead(code uint64)
	CancelWrite(code uint64)
}

// QuicConn is one authenticated (or pre-auth) QUIC connection.
// Hosts adapt quic-go / sing-quic to this interface; go-nowhere never imports quic-go.
type QuicConn interface {
	AcceptStream(ctx context.Context) (QuicStream, error)
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	SendDatagram(b []byte) error
	CloseWithError(code uint64, message string) error
	Close() error
	Context() context.Context
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// QuicListener accepts QuicConn connections.
type QuicListener interface {
	Accept(ctx context.Context) (QuicConn, error)
	Close() error
}
