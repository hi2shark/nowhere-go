// Package bundle orchestrates symmetric/asymmetric Nowhere carrier sessions.
package bundle

import (
	"context"
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
//
// In Nowhere 1.5 the bundle owns the session id and the QUIC auth handshake:
// it generates a session id with crypto/rand, reads the TLS exporter off each
// physical session, opens the first stream, and writes the connection-bound
// auth frame. The injected QUIC backend never learns the session id.
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

	// nextFlowID is the next 1.5 flow id to hand out. Flow ids are uint32 and
	// must skip zero; the allocator wraps within the nonzero u32 space.
	nextFlowID atomic.Uint32
}

// NewCarrierBundle validates options and returns an isolated session bundle.
func NewCarrierBundle(options BundleOptions) (*CarrierBundle, error) {
	if options.TCP == nil {
		return nil, errors.New("nowhere: nil TCP carrier config")
	}
	if !isCarrier(options.Up) || !isCarrier(options.Down) {
		return nil, errors.New("nowhere: invalid carrier selector")
	}
	if (options.Up == wire.CarrierQUIC || options.Down == wire.CarrierQUIC) && options.QUIC == nil {
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
	return value == wire.CarrierTLSTCP || value == wire.CarrierQUIC
}

// SessionID returns the lazily generated identity shared by all bundle carriers.
//
// The session id is generated with crypto/rand and never leaves the bundle for
// QUIC (the TCP carrier needs it to build the auth frame, since the TCP carrier
// performs auth on the physical connection). A random-source failure makes the
// bundle unusable.
func (b *CarrierBundle) SessionID() (wire.SessionID, error) {
	b.sessionIDOnce.Do(func() {
		if _, err := rand.Read(b.sessionID[:]); err != nil {
			b.sessionIDErr = err
			return
		}
		// TCP carrier needs the session id to bind the auth frame to the
		// bundle identity. The QUIC backend is NOT told the session id; the
		// bundle reads the exporter and writes the auth frame itself.
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

// allocFlowID returns the next nonzero uint32 flow id, skipping zero on wrap
// and failing once every nonzero value has been handed out (full u32 cycle).
// The monotonic counter is sufficient because flow ids are never reused within
// an active bundle's lifetime; pending/active tracking lives at the
// session/carrier layer where flows are paired and released.
func (b *CarrierBundle) allocFlowID() (wire.FlowID, error) {
	for {
		next := b.nextFlowID.Load()
		if next == 0 {
			// Should never happen: initialized to 1; treated as exhaustion.
			return 0, ErrFlowIDExhausted
		}
		cand := next + 1
		if cand == 0 {
			// Wrapped past maxuint32: the next valid id is 1. If 1 is already
			// back in circulation this would collide, but a bundle that issues
			// 2^32-1 flows is treated as exhausted instead.
			return 0, ErrFlowIDExhausted
		}
		if b.nextFlowID.CompareAndSwap(next, cand) {
			return next, nil
		}
	}
}

func (b *CarrierBundle) quicClient() (carrier.QuicBackend, error) {
	if b.cfg.up != wire.CarrierQUIC && b.cfg.down != wire.CarrierQUIC {
		return nil, nil
	}
	b.quicOnce.Do(func() {
		sessionID, err := b.SessionID()
		if err != nil {
			b.quicErr = err
			return
		}
		creds := b.cfg.tcp.Credentials()
		if creds == nil {
			b.quicErr = errors.New("nowhere: missing credentials for quic auth")
			return
		}
		auth := func(ctx context.Context, session carrier.QuicSession) error {
			return authenticateQUICSession(ctx, session, creds, wire.AuthTransportQUIC, sessionID)
		}
		b.quic = newQUICMuxBackend(b.cfg.quic, auth)
	})
	return b.quic, b.quicErr
}

// authenticateQUICSession performs the 1.5 connection-bound auth handshake on
// one physical QUIC session: read the TLS exporter off the session, open the
// first stream, and write the 32-byte auth frame followed by FIN (auth-only
// first stream; Go outbound does not coalesce auth with the first flow). The
// session is invalidated on any failure.
func authenticateQUICSession(ctx context.Context, session carrier.QuicSession, creds *wire.Credentials, transport wire.AuthTransport, sessionID wire.SessionID) error {
	if session == nil {
		return errors.New("nowhere: nil quic session")
	}
	exporter, err := session.TLSExporter()
	if err != nil {
		return err
	}
	prep, err := session.PrepareStream(ctx)
	if err != nil {
		return err
	}
	frame := wire.EncodeAuthFrame(creds, transport, exporter, sessionID)
	// Auth-only first stream: commit the frame with finishWrite=true so the
	// stream is half-closed (FIN) after the auth bytes, matching the 1.5 spec.
	if _, err := prep.Commit(ctx, frame[:], true); err != nil {
		_ = prep.Close()
		return err
	}
	return nil
}

func (b *CarrierBundle) tcpPool() (*tcptls.TCPPool, error) {
	if b.cfg.up != wire.CarrierTLSTCP && b.cfg.down != wire.CarrierTLSTCP {
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
