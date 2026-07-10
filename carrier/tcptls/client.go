// Package tcptls is the TLS/TCP carrier pool for Nowhere outbound.
package tcptls

import (
	"context"
	"fmt"
	"net"

	"github.com/hi2shark/go-nowhere/carrier"
	"github.com/hi2shark/go-nowhere/diagnostic"
	"github.com/hi2shark/go-nowhere/wire"
)

const (
	maxPoolSize     = 9
	defaultPoolSize = 5
	// DefaultPoolSize is the protocol-aligned TLS/TCP idle carrier target.
	DefaultPoolSize = defaultPoolSize
)

// TCPDialer establishes the physical TCP carrier connection.
type TCPDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// TLSDialer performs the host-owned TLS client handshake on a carrier.
type TLSDialer interface {
	DialTLSConn(ctx context.Context, conn net.Conn) (net.Conn, error)
}

// TCPRelayMode selects stream or UDP-over-TCP framing.
type TCPRelayMode int

const (
	// TCPRelayTCP selects ordinary stream framing.
	TCPRelayTCP TCPRelayMode = iota
	// TCPRelayUoT selects UDP-over-TCP packet framing.
	TCPRelayUoT
)

// TCPOptions builds an immutable TLS/TCP carrier Config.
type TCPOptions struct {
	Address        string
	ConnectAddress string
	Spec           *wire.EffectiveSpec
	Key            string
	Dialer         TCPDialer
	TLSDialer      TLSDialer
	Observer       diagnostic.Observer
}

// Config is immutable and safe to share between bundles.
type Config struct {
	address        string
	connectAddress string
	spec           *wire.EffectiveSpec
	key            string
	dialer         TCPDialer
	tlsDialer      TLSDialer
	observer       diagnostic.Observer
	sessionID      wire.SessionID
	logger         carrier.Logger
}

// NewConfig validates a TLS/TCP carrier configuration.
func NewConfig(options TCPOptions) (*Config, error) {
	if options.Address == "" {
		return nil, fmt.Errorf("nowhere: empty TCP carrier address")
	}
	if options.Spec == nil {
		return nil, fmt.Errorf("nowhere: nil effective spec")
	}
	if _, err := wire.BuildEffectiveSpec(options.Key, options.Spec.Spec(), options.Spec.ALPN()); err != nil {
		return nil, err
	}
	if options.Dialer == nil {
		return nil, fmt.Errorf("nowhere: nil TCP dialer")
	}
	if options.TLSDialer == nil {
		return nil, fmt.Errorf("nowhere: nil TLS dialer")
	}
	config := &Config{
		address: options.Address, connectAddress: options.ConnectAddress,
		spec: options.Spec, key: options.Key, dialer: options.Dialer,
		tlsDialer: options.TLSDialer, observer: options.Observer,
	}
	config.logger = observerLogger{observer: options.Observer}
	return config, nil
}

// WithSessionID returns a copy bound to one transport bundle identity.
func (c *Config) WithSessionID(sessionID wire.SessionID) *Config {
	if c == nil {
		return nil
	}
	clone := *c
	clone.sessionID = sessionID
	return &clone
}

type observerLogger struct{ observer diagnostic.Observer }

func (l observerLogger) Debugf(format string, args ...any) {
	diagnostic.Emit(context.Background(), l.observer, diagnostic.Event{
		Level: diagnostic.LevelDebug, Code: "carrier_debug", Component: "tcptls",
		Outcome: fmt.Sprintf(format, args...),
	})
}

func (l observerLogger) Warnf(format string, args ...any) {
	diagnostic.Emit(context.Background(), l.observer, diagnostic.Event{
		Level: diagnostic.LevelWarn, Code: "carrier_warning", Component: "tcptls",
		Outcome: fmt.Sprintf(format, args...),
	})
}
