// Package tcptls is the TLS/TCP carrier pool for Nowhere outbound.
package tcptls

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/dialgate"
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

	// DefaultDialBackoffInitial is the first portal dial retry after refused/timeout.
	DefaultDialBackoffInitial = dialgate.DefaultInitial
	// DefaultDialBackoffMax caps portal dial exponential backoff.
	DefaultDialBackoffMax = dialgate.DefaultMax
)

// TCPDialer establishes the physical TCP carrier connection.
type TCPDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// TLSDialer performs the host-owned TLS 1.3 client handshake on a carrier and
// returns the connection together with its TLS exporter. The exporter is
// required for connection-bound authentication; a host that cannot produce one
// must fail the handshake rather than return a zero exporter.
type TLSDialer interface {
	DialTLSConn(ctx context.Context, conn net.Conn) (wire.HandshakedConn, error)
}

// TCPOptions builds an immutable TLS/TCP carrier Config.
type TCPOptions struct {
	Address        string
	ConnectAddress string
	Credentials    *wire.Credentials
	Transport      wire.AuthTransport
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
	// DialBackoffInitial is the first delay after portal connection refused / dial timeout.
	// Zero uses DefaultDialBackoffInitial; negative values are rejected.
	DialBackoffInitial time.Duration
	// DialBackoffMax caps portal dial exponential backoff.
	// Zero uses DefaultDialBackoffMax; negative values are rejected.
	DialBackoffMax time.Duration
}

// Config is immutable and safe to share between bundles.
type Config struct {
	address            string
	connectAddress     string
	credentials        *wire.Credentials
	transport          wire.AuthTransport
	dialer             TCPDialer
	tlsDialer          TLSDialer
	observer           diagnostic.Observer
	sessionID          wire.SessionID
	logger             carrier.Logger
	maxConcurrentDials int
	warmBackoffInitial time.Duration
	warmBackoffMax     time.Duration
	dialBackoffInitial time.Duration
	dialBackoffMax     time.Duration
}

// NewConfig validates a TLS/TCP carrier configuration.
func NewConfig(options TCPOptions) (*Config, error) {
	if options.Address == "" {
		return nil, fmt.Errorf("nowhere: empty TCP carrier address")
	}
	if options.Credentials == nil {
		return nil, fmt.Errorf("nowhere: nil credentials")
	}
	if options.Transport != wire.AuthTransportTLSTCP && options.Transport != wire.AuthTransportQUIC {
		return nil, fmt.Errorf("nowhere: invalid auth transport")
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
	dialInitial := options.DialBackoffInitial
	if dialInitial < 0 {
		return nil, fmt.Errorf("nowhere: dial backoff initial must be >= 0")
	}
	if dialInitial == 0 {
		dialInitial = DefaultDialBackoffInitial
	}
	dialMax := options.DialBackoffMax
	if dialMax < 0 {
		return nil, fmt.Errorf("nowhere: dial backoff max must be >= 0")
	}
	if dialMax == 0 {
		dialMax = DefaultDialBackoffMax
	}
	if dialInitial > dialMax {
		return nil, fmt.Errorf("nowhere: dial backoff initial exceeds max")
	}
	config := &Config{
		address: options.Address, connectAddress: options.ConnectAddress,
		credentials: options.Credentials, transport: options.Transport,
		dialer: options.Dialer,
		tlsDialer: options.TLSDialer, observer: options.Observer,
		maxConcurrentDials: maxDials,
		warmBackoffInitial: warmInitial,
		warmBackoffMax:     warmMax,
		dialBackoffInitial: dialInitial,
		dialBackoffMax:     dialMax,
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

// DialBackoffInitial returns the normalized portal dial backoff floor.
func (c *Config) DialBackoffInitial() time.Duration {
	if c == nil {
		return DefaultDialBackoffInitial
	}
	return c.dialBackoffInitial
}

// DialBackoffMax returns the normalized portal dial backoff ceiling.
func (c *Config) DialBackoffMax() time.Duration {
	if c == nil {
		return DefaultDialBackoffMax
	}
	return c.dialBackoffMax
}

// Observer returns the configured diagnostic observer (may be nil).
func (c *Config) Observer() diagnostic.Observer {
	if c == nil {
		return nil
	}
	return c.observer
}

// Credentials returns the connection-independent authentication credentials.
func (c *Config) Credentials() *wire.Credentials {
	if c == nil {
		return nil
	}
	return c.credentials
}

// Transport returns the physical carrier domain separator bound into auth tags.
func (c *Config) Transport() wire.AuthTransport {
	if c == nil {
		return wire.AuthTransportTLSTCP
	}
	return c.transport
}

type observerLogger struct{ observer diagnostic.Observer }

func (l observerLogger) Debugf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	ev := diagnostic.ParseCarrierLog(msg)
	ev.Level = diagnostic.LevelDebug
	diagnostic.Emit(context.Background(), l.observer, ev)
}

func (l observerLogger) Warnf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	ev := diagnostic.ParseCarrierLog(msg)
	ev.Level = diagnostic.LevelWarn
	if ev.Code == "" || ev.Code == "carrier_debug" {
		ev.Code = "carrier_warning"
	}
	diagnostic.Emit(context.Background(), l.observer, ev)
}
