// Package bundle orchestrates symmetric/asymmetric Nowhere carrier sessions.
package bundle

import (
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/hi2shark/go-nowhere/carrier"
	"github.com/hi2shark/go-nowhere/carrier/tcptls"
	"github.com/hi2shark/go-nowhere/wire"
)

// BundleConfig lazily builds TLS/TCP pool and uses an injected QuicBackend.
type BundleConfig struct {
	// Quic is required when Up or Down is "udp"; nil is OK for tcp/tcp.
	Quic     carrier.QuicBackend
	TCP      *tcptls.TCPConnConfig
	PoolSize int
	Up       string
	Down     string
}

// CarrierBundle shares one session id across carriers and allocates flow ids for asymmetric pairing.
type CarrierBundle struct {
	cfg *BundleConfig

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

func NewCarrierBundle(cfg *BundleConfig) (*CarrierBundle, error) {
	if cfg == nil || cfg.TCP == nil {
		return nil, errors.New("nowhere: nil bundle config")
	}
	if !isCarrier(cfg.Up) || !isCarrier(cfg.Down) {
		return nil, errors.New("nowhere: invalid carrier selector")
	}
	if (cfg.Up == "udp" || cfg.Down == "udp") && cfg.Quic == nil {
		return nil, errors.New("nowhere: nil quic backend")
	}
	b := &CarrierBundle{cfg: cfg}
	b.nextFlowID.Store(1)
	// Pin SessionID before first dial so early QUIC backends share the same id.
	if _, err := b.SessionID(); err != nil {
		return nil, err
	}
	return b, nil
}

func isCarrier(s string) bool { return s == "tcp" || s == "udp" }

func (b *CarrierBundle) SessionID() (wire.SessionID, error) {
	b.sessionIDOnce.Do(func() {
		if _, e := rand.Read(b.sessionID[:]); e != nil {
			b.sessionID = wire.SessionID{}
			b.sessionIDErr = e
			return
		}
		if q := b.cfg.Quic; q != nil {
			q.SetSessionID(b.sessionID)
		}
		b.cfg.TCP.SessionID = b.sessionID
	})
	return b.sessionID, b.sessionIDErr
}

func (b *CarrierBundle) UpCarrier() wire.Carrier   { return carrierFromString(b.cfg.Up) }
func (b *CarrierBundle) DownCarrier() wire.Carrier { return carrierFromString(b.cfg.Down) }
func (b *CarrierBundle) Asymmetric() bool          { return b.cfg.Up != b.cfg.Down }

func (b *CarrierBundle) allocFlowID() uint64 {
	for {
		id := b.nextFlowID.Add(1) - 1
		if id != 0 {
			return id
		}
	}
}

func (b *CarrierBundle) quicClient() (carrier.QuicBackend, error) {
	if b.cfg.Up != "udp" && b.cfg.Down != "udp" {
		return nil, nil
	}
	b.quicOnce.Do(func() {
		if _, err := b.SessionID(); err != nil {
			b.quicErr = err
			return
		}
		b.quic = b.cfg.Quic
	})
	return b.quic, b.quicErr
}

func (b *CarrierBundle) tcpPool() (*tcptls.TCPPool, error) {
	if b.cfg.Up != "tcp" && b.cfg.Down != "tcp" {
		return nil, nil
	}
	b.tcpOnce.Do(func() {
		if _, err := b.SessionID(); err != nil {
			b.tcpErr = err
			return
		}
		b.tcp = tcptls.NewTCPPool(b.cfg.TCP, b.cfg.PoolSize)
	})
	return b.tcp, b.tcpErr
}

func (b *CarrierBundle) QuicBackend() (carrier.QuicBackend, error) { return b.quicClient() }
func (b *CarrierBundle) TCPPool() (*tcptls.TCPPool, error)         { return b.tcpPool() }
func (b *CarrierBundle) PoolTarget() int                           { return b.cfg.PoolSize }

func (b *CarrierBundle) Close() {
	if c, _ := b.quicClient(); c != nil {
		c.Close()
	}
	if p, _ := b.tcpPool(); p != nil {
		p.Close()
	}
}

func carrierFromString(s string) wire.Carrier {
	if s == "tcp" {
		return wire.CarrierTCP
	}
	return wire.CarrierUDP
}

func (b *CarrierBundle) quicClientSync() carrier.QuicBackend {
	c, _ := b.quicClient()
	return c
}

func (b *CarrierBundle) releaseQUICFlow(s carrier.QuicSession, f carrier.QuicUDPFlow) {
	if s == nil || f == nil {
		return
	}
	s.ReleaseUDPAsymmetricFlow(f.FlowID())
}
