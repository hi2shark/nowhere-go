package tcptls

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

// PreparedFlowHalf is an authenticated TLS/TCP carrier that has not yet sent
// a FLOW header or request. Exactly one of Commit or Close must complete;
// sync.Once enforces unique ownership.
type PreparedFlowHalf struct {
	pool   *TCPPool
	cfg    *Config
	conn   net.Conn
	ci     *carrierInfo
	flowID uint64
	dest   string
	header wire.FlowHeader
	mode   TCPRelayMode

	DialQueueMs int64
	RawDialMs   int64
	TLSms       int64
	AuthMs      int64

	once      sync.Once
	committed bool
	closed    bool
}

// PrepareFlowHalf dials, TLS-handshakes, and authenticates without writing FLOW.
// The dial concurrency slot covers dial+TLS+auth only.
func (p *TCPPool) PrepareFlowHalf(ctx context.Context, dest string, header wire.FlowHeader) (*PreparedFlowHalf, error) {
	return p.prepareFlowHalf(ctx, dest, header, TCPRelayTCP)
}

// PrepareUDPFlowHalf prepares a TCP carrier for an asymmetric UDP flow half.
func (p *TCPPool) PrepareUDPFlowHalf(ctx context.Context, dest string, header wire.FlowHeader) (*PreparedFlowHalf, error) {
	return p.prepareFlowHalf(ctx, dest, header, TCPRelayUoT)
}

func (p *TCPPool) prepareFlowHalf(ctx context.Context, dest string, header wire.FlowHeader, mode TCPRelayMode) (*PreparedFlowHalf, error) {
	if p == nil {
		return nil, errors.New("nowhere: tcp pool unavailable")
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return nil, errors.New("nowhere: tcp pool closed")
	}

	queueStart := time.Now()
	release, err := p.acquireDialSlot(ctx)
	if err != nil {
		return nil, err
	}
	dialQueueMs := time.Since(queueStart).Milliseconds()

	half, err := prepareAuthenticatedLane(ctx, p.cfg, header.FlowID, dest, header, mode)
	release()
	if err != nil {
		return nil, err
	}
	half.pool = p
	half.DialQueueMs = dialQueueMs
	return half, nil
}

// Commit writes the FLOW header and request, transferring ownership of the conn.
func (h *PreparedFlowHalf) Commit() (net.Conn, error) {
	if h == nil {
		return nil, errors.New("nowhere: nil prepared flow half")
	}
	var (
		conn net.Conn
		err  error
	)
	h.once.Do(func() {
		if h.closed || h.conn == nil || h.ci == nil {
			err = errors.New("nowhere: prepared flow half closed")
			return
		}
		timing := newOpenTiming()
		network := relayNetwork(h.mode)
		stage := "flow_commit"
		if h.mode == TCPRelayUoT {
			stage = "udp_flow_commit"
		}
		env, envErr := wire.WriteFlowHeader(h.header)
		if envErr != nil {
			err = envErr
			h.forceClose()
			return
		}
		req, reqErr := wire.EncodeTCPRequest(h.dest, h.cfg.spec)
		if reqErr != nil {
			err = reqErr
			h.forceClose()
			return
		}
		buf := make([]byte, 0, len(env)+len(req))
		buf = append(buf, env[:]...)
		buf = append(buf, req...)
		timing.requestWrite, err = writeFullTimed(h.conn, buf)
		if err != nil {
			logOpenTiming(h.cfg, "fresh_failed", h.flowID, h.ci.id, stage, network, h.dest, timing)
			h.forceClose()
			return
		}
		h.ci.transition(stateRequestSent)
		h.ci.transition(stateConsumed)
		logOpenTiming(h.cfg, "fresh", h.flowID, h.ci.id, stage, network, h.dest, timing)
		loggerFrom(h.cfg).Debugf("[Nowhere] [carrier] request_sent flow_id=%d carrier_id=%d target=%s consumed=true",
			h.flowID, h.ci.id, h.dest)
		conn = wrapRelay(h.conn, h.ci, h.flowID, h.mode, h.dest)
		h.conn = nil
		h.committed = true
	})
	if err != nil {
		return nil, err
	}
	if !h.committed || conn == nil {
		return nil, errors.New("nowhere: prepared flow half already closed")
	}
	return conn, nil
}

// Close abandons a prepared half that was never committed.
func (h *PreparedFlowHalf) Close() error {
	if h == nil {
		return nil
	}
	var err error
	h.once.Do(func() {
		h.closed = true
		err = h.forceClose()
	})
	return err
}

func (h *PreparedFlowHalf) forceClose() error {
	if h.conn == nil {
		return nil
	}
	if h.ci != nil {
		h.ci.transition(stateClosing)
	}
	err := h.conn.Close()
	if h.ci != nil {
		h.ci.transition(stateClosed)
	}
	h.conn = nil
	return err
}

// CarrierID returns the local diagnostic carrier id.
func (h *PreparedFlowHalf) CarrierID() uint64 {
	if h == nil || h.ci == nil {
		return 0
	}
	return h.ci.id
}

// FlowID returns the wire flow id used for correlation.
func (h *PreparedFlowHalf) FlowID() uint64 {
	if h == nil {
		return 0
	}
	return h.flowID
}

func prepareAuthenticatedLane(ctx context.Context, cfg *Config, flowID uint64, dest string, header wire.FlowHeader, mode TCPRelayMode) (*PreparedFlowHalf, error) {
	ci := newCarrierInfo(loggerFrom(cfg))
	timing := newOpenTiming()
	stage := "flow_prepare"
	network := relayNetwork(mode)
	if mode == TCPRelayUoT {
		stage = "udp_flow_prepare"
	}
	role := "asymmetric_tcp"
	if mode == TCPRelayUoT {
		role = "asymmetric_uot"
	}
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] flow_start flow_id=%d carrier_id=%d role=%s target=%s stage=prepare", flowID, ci.id, role, dest)
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] dial_start carrier_id=%d flow_id=%d stage=%s", ci.id, flowID, stage)
	ci.transition(stateBorrowed)

	rawDialStart := time.Now()
	raw, err := cfg.dialer.DialContext(ctx, "tcp", dialAddr(cfg))
	timing.rawDial = time.Since(rawDialStart)
	if err != nil {
		ci.transition(stateClosed)
		logOpenTiming(cfg, "fresh_failed", flowID, ci.id, stage, network, dest, timing)
		return nil, err
	}
	tuneNowhereTCPConn(cfg, raw, ci.id, stage)

	tlsStart := time.Now()
	tlsConn, err := cfg.tlsDialer.DialTLSConn(ctx, raw)
	timing.tlsHandshake = time.Since(tlsStart)
	if err != nil {
		_ = raw.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, "fresh_failed", flowID, ci.id, stage, network, dest, timing)
		return nil, err
	}

	auth, err := tcpAuthFrame(cfg)
	if err != nil {
		_ = tlsConn.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, "fresh_failed", flowID, ci.id, stage, network, dest, timing)
		return nil, err
	}
	timing.authWrite, err = writeFullTimed(tlsConn, auth)
	if err != nil {
		_ = tlsConn.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, "fresh_failed", flowID, ci.id, stage, network, dest, timing)
		return nil, err
	}

	logOpenTiming(cfg, "fresh_prepare", flowID, ci.id, stage, network, dest, timing)
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] auth_ok carrier_id=%d flow_id=%d stage=prepare", ci.id, flowID)

	return &PreparedFlowHalf{
		cfg:       cfg,
		conn:      tlsConn,
		ci:        ci,
		flowID:    flowID,
		dest:      dest,
		header:    header,
		mode:      mode,
		RawDialMs: timing.rawDial.Milliseconds(),
		TLSms:     timing.tlsHandshake.Milliseconds(),
		AuthMs:    timing.authWrite.Milliseconds(),
	}, nil
}

// AcquireFlowHalf opens a fresh lane with flow envelope + TCP request (no warm pool).
// Prefer PrepareFlowHalf + Commit for mixed two-phase open.
func (p *TCPPool) AcquireFlowHalf(ctx context.Context, dest string, header wire.FlowHeader) (net.Conn, error) {
	half, err := p.PrepareFlowHalf(ctx, dest, header)
	if err != nil {
		return nil, err
	}
	conn, err := half.Commit()
	if err != nil {
		_ = half.Close()
		return nil, err
	}
	return conn, nil
}

// AcquireUDPFlowHalf opens a fresh TCP lane for an asymmetric UDP flow half.
func (p *TCPPool) AcquireUDPFlowHalf(ctx context.Context, dest string, header wire.FlowHeader) (net.Conn, error) {
	half, err := p.PrepareUDPFlowHalf(ctx, dest, header)
	if err != nil {
		return nil, err
	}
	conn, err := half.Commit()
	if err != nil {
		_ = half.Close()
		return nil, err
	}
	return conn, nil
}
