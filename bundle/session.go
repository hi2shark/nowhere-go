// Package bundle orchestrates symmetric/asymmetric Nowhere carrier sessions.
package bundle

import (
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

// BundleOptions builds an immutable carrier bundle.
type BundleOptions struct {
	QUIC           carrier.QuicBackend
	TCP            *tcptls.Config
	PoolSize       int
	PrewarmOnStart bool
	Up             wire.Carrier
	Down           wire.Carrier
}

type bundleConfig struct {
	quic           carrier.QuicBackend
	tcp            *tcptls.Config
	poolSize       int
	prewarmOnStart bool
	up             wire.Carrier
	down           wire.Carrier
}

// CarrierBundle shares one session id across carriers and allocates flow ids.
type CarrierBundle struct {
	cfg bundleConfig

	sessionIDOnce sync.Once
	sessionID     wire.SessionID
	sessionIDErr  error

	quicOnce sync.Once
	quic     carrier.QuicBackend
	quicErr  error

	tcpOnce sync.Once
	tcp     *tcptls.TCPPool
	tcpErr  error

	nextFlowID atomic.Uint64
}

// NewCarrierBundle validates options and returns an isolated session bundle.
func NewCarrierBundle(options BundleOptions) (*CarrierBundle, error) {
	if options.TCP == nil {
		return nil, errors.New("nowhere: nil TCP carrier config")
	}
	if !isCarrier(options.Up) || !isCarrier(options.Down) {
		return nil, errors.New("nowhere: invalid carrier selector")
	}
	if (options.Up == wire.CarrierUDP || options.Down == wire.CarrierUDP) && options.QUIC == nil {
		return nil, errors.New("nowhere: nil quic backend")
	}
	if options.PoolSize < 0 {
		return nil, errors.New("nowhere: negative pool size")
	}
	bundle := &CarrierBundle{cfg: bundleConfig{
		quic: options.QUIC, tcp: options.TCP, poolSize: options.PoolSize,
		prewarmOnStart: options.PrewarmOnStart,
		up:             options.Up, down: options.Down,
	}}
	bundle.nextFlowID.Store(1)
	if _, err := bundle.SessionID(); err != nil {
		return nil, err
	}
	if options.PrewarmOnStart && options.PoolSize > 0 {
		if _, err := bundle.tcpPool(); err != nil {
			return nil, err
		}
	}
	return bundle, nil
}

func isCarrier(value wire.Carrier) bool {
	return value == wire.CarrierTCP || value == wire.CarrierUDP
}

// SessionID returns the lazily generated identity shared by all bundle carriers.
func (b *CarrierBundle) SessionID() (wire.SessionID, error) {
	b.sessionIDOnce.Do(func() {
		if _, err := rand.Read(b.sessionID[:]); err != nil {
			b.sessionIDErr = err
			return
		}
		if b.cfg.quic != nil {
			b.cfg.quic.SetSessionID(b.sessionID)
		}
		b.cfg.tcp = b.cfg.tcp.WithSessionID(b.sessionID)
	})
	return b.sessionID, b.sessionIDErr
}

// UpCarrier returns the configured uplink carrier.
func (b *CarrierBundle) UpCarrier() wire.Carrier { return b.cfg.up }

// DownCarrier returns the configured downlink carrier.
func (b *CarrierBundle) DownCarrier() wire.Carrier { return b.cfg.down }

// Asymmetric reports whether uplink and downlink use different carriers.
func (b *CarrierBundle) Asymmetric() bool { return b.cfg.up != b.cfg.down }

// PoolTarget returns the configured TLS/TCP idle-pool target.
func (b *CarrierBundle) PoolTarget() int { return b.cfg.poolSize }

// ErrFlowIDExhausted is returned after a bundle has allocated every nonzero flow ID.
var ErrFlowIDExhausted = errors.New("nowhere: flow id space exhausted")

func (b *CarrierBundle) allocFlowID() (uint64, error) {
	for {
		next := b.nextFlowID.Load()
		if next == 0 {
			return 0, ErrFlowIDExhausted
		}
		if b.nextFlowID.CompareAndSwap(next, next+1) {
			return next, nil
		}
	}
}

func (b *CarrierBundle) quicClient() (carrier.QuicBackend, error) {
	if b.cfg.up != wire.CarrierUDP && b.cfg.down != wire.CarrierUDP {
		return nil, nil
	}
	b.quicOnce.Do(func() {
		if _, err := b.SessionID(); err != nil {
			b.quicErr = err
			return
		}
		b.quic = newQUICMuxBackend(b.cfg.quic)
	})
	return b.quic, b.quicErr
}

func (b *CarrierBundle) tcpPool() (*tcptls.TCPPool, error) {
	if b.cfg.up != wire.CarrierTCP && b.cfg.down != wire.CarrierTCP {
		return nil, nil
	}
	b.tcpOnce.Do(func() {
		if _, err := b.SessionID(); err != nil {
			b.tcpErr = err
			return
		}
		b.tcp = tcptls.NewTCPPool(b.cfg.tcp, b.cfg.poolSize)
		if b.tcp == nil {
			b.tcpErr = errors.New("nowhere: invalid TCP pool config")
		} else if b.cfg.prewarmOnStart && b.cfg.poolSize > 0 {
			b.tcp.Prewarm()
		}
	})
	return b.tcp, b.tcpErr
}

// Close releases initialized carrier resources. It is safe on a nil bundle.
func (b *CarrierBundle) Close() {
	if b == nil {
		return
	}
	if client, _ := b.quicClient(); client != nil {
		client.Close()
	}
	if pool, _ := b.tcpPool(); pool != nil {
		pool.Close()
	}
}
