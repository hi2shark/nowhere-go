package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/go-nowhere/wire"
)

type pairKey struct {
	session wire.SessionID
	flowID  uint64
}

type pairMetadata struct {
	kind   wire.FlowKind
	target string
	up     wire.Carrier
	down   wire.Carrier
}

func metadataFrom(header wire.FlowHeader, target string) pairMetadata {
	return pairMetadata{kind: header.Kind, target: target, up: header.Uplink, down: header.Downlink}
}

func (m pairMetadata) equal(other pairMetadata) bool {
	return m.kind == other.kind && m.target == other.target && m.up == other.up && m.down == other.down
}

type pairState uint8

const (
	pairWaiting pairState = iota
	pairCompleted
	pairFailed
)

type pendingFlow struct {
	meta  pairMetadata
	role  wire.FlowRole
	tcp   net.Conn
	udp   udpHalf
	timer *time.Timer
	done  chan struct{}
	state pairState
	err   error
}

// flowPairManager pairs asymmetric FLOW_OPEN / FLOW_ATTACH halves.
// It is retained as a named type for internal tests; Handler owns its lifecycle.
type flowPairManager struct {
	timeout time.Duration

	mu            sync.Mutex
	pending       map[pairKey]*pendingFlow
	perSession    map[wire.SessionID]int
	maxPerSession int
	maxGlobal     int
	closed        bool
}

func newFlowPairManager(timeout time.Duration) *flowPairManager {
	if timeout <= 0 {
		timeout = DefaultFlowPairTimeout
	}
	return &flowPairManager{
		timeout:       timeout,
		pending:       make(map[pairKey]*pendingFlow),
		perSession:    make(map[wire.SessionID]int),
		maxPerSession: DefaultPendingPairsPerSession,
		maxGlobal:     DefaultPendingPairsGlobal,
	}
}

func (m *flowPairManager) configureLimits(limits Limits) {
	m.mu.Lock()
	m.maxPerSession = limits.PendingPairsPerSession
	m.maxGlobal = limits.PendingPairsGlobal
	m.mu.Unlock()
}

func (m *flowPairManager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	pending := make([]*pendingFlow, 0, len(m.pending))
	for key, half := range m.pending {
		if half.timer != nil {
			half.timer.Stop()
		}
		half.state = pairFailed
		half.err = ErrClosed
		close(half.done)
		pending = append(pending, half)
		delete(m.pending, key)
	}
	m.perSession = make(map[wire.SessionID]int)
	m.mu.Unlock()
	for _, half := range pending {
		closePendingFlowWithError(half, ErrClosed)
	}
}

// SubmitTCP caches or pairs a TCP half.
func (m *flowPairManager) SubmitTCP(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target string, conn net.Conn) (net.Conn, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: nil tcp half", ErrInvalidHandler)
	}
	if err := validatePairHeader(header, wire.FlowKindTCP); err != nil {
		return nil, err
	}
	pending := &pendingFlow{
		meta: metadataFrom(header, target), role: header.Role, tcp: conn,
		done: make(chan struct{}), state: pairWaiting,
	}
	existing, err := m.submit(pairKey{session: sessionID, flowID: header.FlowID}, pending)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, m.wait(ctx, pairKey{session: sessionID, flowID: header.FlowID}, pending)
	}
	var openConn, attachConn net.Conn
	if header.Role == wire.FlowRoleOpen {
		openConn, attachConn = conn, existing.tcp
	} else {
		openConn, attachConn = existing.tcp, conn
	}
	return &splicedConn{
		reader: openConn,
		writer: attachConn,
		closer: []io.Closer{openConn, attachConn},
		remote: openConn.RemoteAddr(),
		local:  openConn.LocalAddr(),
	}, nil
}

// submit returns the existing complementary half, or nil when current is stored.
func (m *flowPairManager) submit(key pairKey, current *pendingFlow) (*pendingFlow, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrClosed
	}
	if existing, ok := m.pending[key]; ok {
		if !existing.meta.equal(current.meta) {
			err := fmt.Errorf("%w: flow=%d", ErrCarrierMismatch, key.flowID)
			m.failExistingLocked(key, existing, err)
			m.mu.Unlock()
			closePendingFlowWithError(existing, err)
			closePendingFlowWithError(current, err)
			return nil, err
		}
		if existing.role == current.role {
			err := fmt.Errorf("%w: flow=%d role=%d", ErrDuplicateHalf, key.flowID, current.role)
			m.failExistingLocked(key, existing, err)
			m.mu.Unlock()
			closePendingFlowWithError(existing, err)
			closePendingFlowWithError(current, err)
			return nil, err
		}
		m.removeLocked(key, existing)
		existing.state = pairCompleted
		existing.err = nil
		close(existing.done)
		m.mu.Unlock()
		return existing, nil
	}
	if len(m.pending) >= m.maxGlobal || m.perSession[key.session] >= m.maxPerSession {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: session=%x", ErrPairLimit, key.session)
	}
	current.timer = time.AfterFunc(m.timeout, func() { m.timeoutFlow(key, current) })
	m.pending[key] = current
	m.perSession[key.session]++
	m.mu.Unlock()
	return nil, nil
}

func (m *flowPairManager) wait(ctx context.Context, key pairKey, pending *pendingFlow) error {
	select {
	case <-pending.done:
		m.mu.Lock()
		state, err := pending.state, pending.err
		m.mu.Unlock()
		if state == pairCompleted {
			return nil
		}
		return err
	case <-ctx.Done():
		m.mu.Lock()
		if current, ok := m.pending[key]; ok && current == pending && pending.state == pairWaiting {
			m.removeLocked(key, pending)
			pending.state = pairFailed
			pending.err = ctx.Err()
			close(pending.done)
			m.mu.Unlock()
			closePendingFlowWithError(pending, ctx.Err())
			return ctx.Err()
		}
		state, err := pending.state, pending.err
		m.mu.Unlock()
		if state == pairCompleted {
			return nil
		}
		if err != nil {
			return err
		}
		return ctx.Err()
	}
}

func (m *flowPairManager) timeoutFlow(key pairKey, pending *pendingFlow) {
	m.mu.Lock()
	if current, ok := m.pending[key]; !ok || current != pending || pending.state != pairWaiting {
		m.mu.Unlock()
		return
	}
	m.removeLocked(key, pending)
	err := fmt.Errorf("%w: flow=%d", ErrPairTimeout, key.flowID)
	pending.state = pairFailed
	pending.err = err
	close(pending.done)
	m.mu.Unlock()
	closePendingFlowWithError(pending, err)
}

func (m *flowPairManager) failExistingLocked(key pairKey, existing *pendingFlow, err error) {
	m.removeLocked(key, existing)
	existing.state = pairFailed
	existing.err = err
	close(existing.done)
}

func (m *flowPairManager) removeLocked(key pairKey, pending *pendingFlow) {
	delete(m.pending, key)
	if pending.timer != nil {
		pending.timer.Stop()
	}
	if count := m.perSession[key.session]; count <= 1 {
		delete(m.perSession, key.session)
	} else {
		m.perSession[key.session] = count - 1
	}
}

func validatePairHeader(header wire.FlowHeader, kind wire.FlowKind) error {
	if header.Kind != kind || header.FlowID == 0 {
		return fmt.Errorf("%w: invalid flow header", ErrUnsupportedFlow)
	}
	if header.Role != wire.FlowRoleOpen && header.Role != wire.FlowRoleAttach {
		return fmt.Errorf("%w: invalid role", ErrUnsupportedFlow)
	}
	if header.Uplink == header.Downlink ||
		(header.Uplink != wire.CarrierTCP && header.Uplink != wire.CarrierUDP) ||
		(header.Downlink != wire.CarrierTCP && header.Downlink != wire.CarrierUDP) {
		return fmt.Errorf("%w: invalid carriers", ErrCarrierMismatch)
	}
	return nil
}

func closePendingFlowWithError(pending *pendingFlow, err error) {
	if pending == nil {
		return
	}
	if pending.tcp != nil {
		closeConnWithError(pending.tcp, err)
	}
	closeUDPHalfWithError(pending.udp, err)
}

type splicedConn struct {
	reader io.Reader
	writer io.Writer
	closer []io.Closer
	remote net.Addr
	local  net.Addr
	once   sync.Once
}

func (c *splicedConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *splicedConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *splicedConn) Close() (err error) {
	c.once.Do(func() {
		for _, closer := range c.closer {
			if closeErr := closer.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
		}
	})
	return err
}

func (c *splicedConn) closeWithError(cause error) {
	c.once.Do(func() {
		for _, closer := range c.closer {
			if conn, ok := closer.(net.Conn); ok {
				closeConnWithError(conn, cause)
			} else {
				_ = closer.Close()
			}
		}
	})
}
func (c *splicedConn) LocalAddr() net.Addr  { return c.local }
func (c *splicedConn) RemoteAddr() net.Addr { return c.remote }
func (c *splicedConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
func (c *splicedConn) SetReadDeadline(t time.Time) error {
	if deadline, ok := c.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		return deadline.SetReadDeadline(t)
	}
	return nil
}
func (c *splicedConn) SetWriteDeadline(t time.Time) error {
	if deadline, ok := c.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return deadline.SetWriteDeadline(t)
	}
	return nil
}

var _ net.Conn = (*splicedConn)(nil)
