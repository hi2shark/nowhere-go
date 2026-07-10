package server

import (
	"fmt"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

const (
	// DefaultTLSHandshakeTimeout bounds the host-provided TLS handshake.
	DefaultTLSHandshakeTimeout = 5 * time.Second
	// DefaultAuthTimeout is the center of the jittered authentication deadline.
	DefaultAuthTimeout = 5 * time.Second
	// DefaultRequestIdleTimeout bounds the first request after authentication.
	DefaultRequestIdleTimeout = 40 * time.Second
	// DefaultUOTSetupTimeout bounds UDP-over-TCP setup framing.
	DefaultUOTSetupTimeout = 5 * time.Second
	// DefaultFlowPairTimeout bounds asymmetric half pairing.
	DefaultFlowPairTimeout = 5 * time.Second
	// DefaultUDPIdleTimeout closes inactive UDP flows.
	DefaultUDPIdleTimeout = 120 * time.Second
	// DefaultTCPReadGrace bounds the remaining relay direction after half-close.
	DefaultTCPReadGrace = 30 * time.Second
)

const (
	// DefaultPendingPairsPerSession limits unmatched halves in one session.
	DefaultPendingPairsPerSession = 1024
	// DefaultPendingPairsGlobal limits unmatched halves process-wide.
	DefaultPendingPairsGlobal = 4096
	// DefaultQUICFlowsPerSession limits active UDP flows in one QUIC session.
	DefaultQUICFlowsPerSession = 256
	// DefaultQUICQueueBytes is the shared datagram queue byte budget per session.
	DefaultQUICQueueBytes = 4 * 1024 * 1024
	// DefaultQUICQueuePackets limits queued datagrams per flow.
	DefaultQUICQueuePackets = 64
	// DefaultActiveQUICSessions limits authenticated QUIC sessions.
	DefaultActiveQUICSessions = 1024
)

// Network selects a Portal ingress carrier.
type Network string

const (
	// NetworkTCP enables TLS-over-TCP carriers.
	NetworkTCP Network = "tcp"
	// NetworkUDP enables QUIC/UDP carriers.
	NetworkUDP Network = "udp"
)

// Timeouts controls bounded server operations. Zero values use protocol defaults.
type Timeouts struct {
	TLSHandshake time.Duration
	Auth         time.Duration
	RequestIdle  time.Duration
	UOTSetup     time.Duration
	FlowPair     time.Duration
	UDPIdle      time.Duration
	TCPReadGrace time.Duration
}

// Limits controls process and session resource bounds. Zero values use defaults.
type Limits struct {
	PendingPairsPerSession int
	PendingPairsGlobal     int
	QUICFlowsPerSession    int
	QUICQueueBytes         int
	QUICQueuePackets       int
	ActiveQUICSessions     int
}

// ConfigOptions builds an immutable server Config.
type ConfigOptions struct {
	Password string
	Spec     string
	ALPN     string
	Networks []Network
	Timeouts Timeouts
	Limits   Limits
}

// Config is normalized and immutable after construction.
type Config struct {
	key       string
	spec      *wire.EffectiveSpec
	networks  []Network
	enableTCP bool
	enableUDP bool
	timeouts  Timeouts
	limits    Limits
}

// NewConfig validates and normalizes server configuration.
func NewConfig(options ConfigOptions) (*Config, error) {
	es, err := wire.BuildEffectiveSpec(options.Password, options.Spec, options.ALPN)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	timeouts, err := normalizeTimeouts(options.Timeouts)
	if err != nil {
		return nil, err
	}
	limits, err := normalizeLimits(options.Limits)
	if err != nil {
		return nil, err
	}
	networks := options.Networks
	if len(networks) == 0 {
		networks = []Network{NetworkTCP, NetworkUDP}
	}
	seen := make(map[Network]struct{}, len(networks))
	cfg := &Config{
		key:      options.Password,
		spec:     es,
		timeouts: timeouts,
		limits:   limits,
		networks: append([]Network(nil), networks...),
	}
	for _, network := range networks {
		if _, exists := seen[network]; exists {
			return nil, fmt.Errorf("%w: duplicate network %q", ErrInvalidConfig, network)
		}
		seen[network] = struct{}{}
		switch network {
		case NetworkTCP:
			cfg.enableTCP = true
		case NetworkUDP:
			cfg.enableUDP = true
		default:
			return nil, fmt.Errorf("%w: unsupported network %q", ErrInvalidConfig, network)
		}
	}
	return cfg, nil
}

func normalizeTimeouts(value Timeouts) (Timeouts, error) {
	defaults := Timeouts{
		TLSHandshake: DefaultTLSHandshakeTimeout,
		Auth:         DefaultAuthTimeout,
		RequestIdle:  DefaultRequestIdleTimeout,
		UOTSetup:     DefaultUOTSetupTimeout,
		FlowPair:     DefaultFlowPairTimeout,
		UDPIdle:      DefaultUDPIdleTimeout,
		TCPReadGrace: DefaultTCPReadGrace,
	}
	fields := []struct {
		name string
		in   *time.Duration
		out  *time.Duration
	}{
		{"tls handshake timeout", &value.TLSHandshake, &defaults.TLSHandshake},
		{"auth timeout", &value.Auth, &defaults.Auth},
		{"request idle timeout", &value.RequestIdle, &defaults.RequestIdle},
		{"uot setup timeout", &value.UOTSetup, &defaults.UOTSetup},
		{"flow pair timeout", &value.FlowPair, &defaults.FlowPair},
		{"udp idle timeout", &value.UDPIdle, &defaults.UDPIdle},
		{"tcp read grace", &value.TCPReadGrace, &defaults.TCPReadGrace},
	}
	for _, field := range fields {
		if *field.in < 0 {
			return Timeouts{}, fmt.Errorf("%w: negative %s", ErrInvalidConfig, field.name)
		}
		if *field.in > 0 {
			*field.out = *field.in
		}
	}
	return defaults, nil
}

func normalizeLimits(value Limits) (Limits, error) {
	defaults := Limits{
		PendingPairsPerSession: DefaultPendingPairsPerSession,
		PendingPairsGlobal:     DefaultPendingPairsGlobal,
		QUICFlowsPerSession:    DefaultQUICFlowsPerSession,
		QUICQueueBytes:         DefaultQUICQueueBytes,
		QUICQueuePackets:       DefaultQUICQueuePackets,
		ActiveQUICSessions:     DefaultActiveQUICSessions,
	}
	fields := []struct {
		name string
		in   *int
		out  *int
	}{
		{"pending pairs per-session", &value.PendingPairsPerSession, &defaults.PendingPairsPerSession},
		{"pending pairs global", &value.PendingPairsGlobal, &defaults.PendingPairsGlobal},
		{"quic flows per-session", &value.QUICFlowsPerSession, &defaults.QUICFlowsPerSession},
		{"quic queue bytes", &value.QUICQueueBytes, &defaults.QUICQueueBytes},
		{"quic queue packets", &value.QUICQueuePackets, &defaults.QUICQueuePackets},
		{"active quic sessions", &value.ActiveQUICSessions, &defaults.ActiveQUICSessions},
	}
	for _, field := range fields {
		if *field.in < 0 {
			return Limits{}, fmt.Errorf("%w: negative %s", ErrInvalidConfig, field.name)
		}
		if *field.in > 0 {
			*field.out = *field.in
		}
	}
	if defaults.PendingPairsPerSession > defaults.PendingPairsGlobal {
		return Limits{}, fmt.Errorf("%w: per-session pair limit exceeds global limit", ErrInvalidConfig)
	}
	return defaults, nil
}

// TCPEnabled reports whether TCP ingress is enabled.
func (c *Config) TCPEnabled() bool { return c != nil && c.enableTCP }

// UDPEnabled reports whether QUIC/UDP ingress is enabled.
func (c *Config) UDPEnabled() bool { return c != nil && c.enableUDP }

// Networks returns a defensive copy of the configured ingress carriers.
func (c *Config) Networks() []Network {
	if c == nil {
		return nil
	}
	return append([]Network(nil), c.networks...)
}

// EffectiveSpec returns the immutable derived protocol specification.
func (c *Config) EffectiveSpec() *wire.EffectiveSpec {
	if c == nil {
		return nil
	}
	return c.spec
}

// ALPN returns the normalized application protocol identifier.
func (c *Config) ALPN() string {
	if c == nil || c.spec == nil {
		return ""
	}
	return c.spec.ALPN()
}

// SpecID returns the derived protocol specification identifier.
func (c *Config) SpecID() string {
	if c == nil || c.spec == nil {
		return ""
	}
	return c.spec.SpecID()
}

// Timeouts returns the normalized timeout values by value.
func (c *Config) Timeouts() Timeouts {
	if c == nil {
		return Timeouts{}
	}
	return c.timeouts
}

// Limits returns the normalized resource limits by value.
func (c *Config) Limits() Limits {
	if c == nil {
		return Limits{}
	}
	return c.limits
}
