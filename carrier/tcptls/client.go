// Package tcptls is the TLS/TCP carrier pool for Nowhere outbound.
// Hosts inject TCPDialer and TlsDialer.
package tcptls

import (
	"context"
	"net"

	"github.com/hi2shark/go-nowhere/carrier"
	"github.com/hi2shark/go-nowhere/wire"
)

const (
	maxPoolSize     = 9
	defaultPoolSize = 5
	DefaultPoolSize = defaultPoolSize
)

type TCPDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type TlsDialer interface {
	DialTLSConn(ctx context.Context, c net.Conn) (net.Conn, error)
}

type TCPRelayMode int

const (
	TCPRelayTCP TCPRelayMode = iota
	TCPRelayUoT
)

type TCPConnConfig struct {
	Addr        string
	ConnectAddr string
	Spec        *wire.EffectiveSpec
	Key         string
	Dialer      TCPDialer
	TLSDialer   TlsDialer
	// Logger is optional; nil uses carrier.NopLogger.
	Logger      carrier.Logger
	// SessionID pins bundle identity for asymmetric pairing; zero generates per lane.
	SessionID wire.SessionID
}
