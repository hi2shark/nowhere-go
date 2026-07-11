// Package tcptls is the TLS/TCP carrier pool for Nowhere outbound.
package tcptls

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/diagnostic"
	"github.com/hi2shark/nowhere-go/wire"
)

const (
	maxPoolSize     = 9
	defaultPoolSize = 5
	// DefaultPoolSize is the protocol-aligned TLS/TCP idle carrier target.
	DefaultPoolSize = defaultPoolSize

	// DefaultMaxConcurrentDials caps in-flight physical TCP dials per outbound.
	// Conservative default for mixed TCP/QUIC bursts (dial+TLS+auth share the slot).
	DefaultMaxConcurrentDials = 16
	// DefaultWarmBackoffInitial is the first warm-prepare retry delay after failure.
	DefaultWarmBackoffInitial = time.Second
	// DefaultWarmBackoffMax caps exponential warm-prepare backoff.
	DefaultWarmBackoffMax = 30 * time.Second
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

	// MaxConcurrentDials limits in-flight physical dials (TCP+TLS+auth) per pool.
	// Zero uses DefaultMaxConcurrentDials; negative values are rejected.
	MaxConcurrentDials int
	// WarmBackoffInitial is the first delay after a warm-prepare failure.
	// Zero uses DefaultWarmBackoffInitial; negative values are rejected.
	WarmBackoffInitial time.Duration
	// WarmBackoffMax caps warm-prepare exponential backoff.
	// Zero uses DefaultWarmBackoffMax; negative values are rejected.
	WarmBackoffMax time.Duration
}

// Config is immutable and safe to share between bundles.
type Config struct {
	address            string
	connectAddress     string
	spec               *wire.EffectiveSpec
	key                string
	dialer             TCPDialer
	tlsDialer          TLSDialer
	observer           diagnostic.Observer
	sessionID          wire.SessionID
	logger             carrier.Logger
	maxConcurrentDials int
	warmBackoffInitial time.Duration
	warmBackoffMax     time.Duration
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
	maxDials := options.MaxConcurrentDials
	if maxDials < 0 {
		return nil, fmt.Errorf("nowhere: max concurrent dials must be >= 0")
	}
	if maxDials == 0 {
		maxDials = DefaultMaxConcurrentDials
	}
	warmInitial := options.WarmBackoffInitial
	if warmInitial < 0 {
		return nil, fmt.Errorf("nowhere: warm backoff initial must be >= 0")
	}
	if warmInitial == 0 {
		warmInitial = DefaultWarmBackoffInitial
	}
	warmMax := options.WarmBackoffMax
	if warmMax < 0 {
		return nil, fmt.Errorf("nowhere: warm backoff max must be >= 0")
	}
	if warmMax == 0 {
		warmMax = DefaultWarmBackoffMax
	}
	if warmInitial > warmMax {
		return nil, fmt.Errorf("nowhere: warm backoff initial exceeds max")
	}
	config := &Config{
		address: options.Address, connectAddress: options.ConnectAddress,
		spec: options.Spec, key: options.Key, dialer: options.Dialer,
		tlsDialer: options.TLSDialer, observer: options.Observer,
		maxConcurrentDials: maxDials,
		warmBackoffInitial: warmInitial,
		warmBackoffMax:     warmMax,
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

// MaxConcurrentDials returns the normalized dial concurrency cap.
func (c *Config) MaxConcurrentDials() int {
	if c == nil {
		return DefaultMaxConcurrentDials
	}
	return c.maxConcurrentDials
}

// WarmBackoffInitial returns the normalized warm-prepare backoff floor.
func (c *Config) WarmBackoffInitial() time.Duration {
	if c == nil {
		return DefaultWarmBackoffInitial
	}
	return c.warmBackoffInitial
}

// WarmBackoffMax returns the normalized warm-prepare backoff ceiling.
func (c *Config) WarmBackoffMax() time.Duration {
	if c == nil {
		return DefaultWarmBackoffMax
	}
	return c.warmBackoffMax
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
