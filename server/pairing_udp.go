package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

type udpPairPhase uint8

const (
	udpPairWaiting udpPairPhase = iota
	udpPairPaired
	udpPairActive
	udpPairClosed
)

type udpPairRecord struct {
	meta        pairMetadata
	waitingRole wire.FlowRole
	transport   string
	open        udpHalf
	attach      udpHalf
	paired      *pairedUDP
	active      *pairedUDPConn
	handle      *udpPairHandle
	staged      bool
	onFinish    func(error)
	timer       *time.Timer
	done        chan struct{}
	phase       udpPairPhase
	err         error
	started     time.Time
	sessionID   wire.SessionID
	flowID      uint64
	source      net.Addr
}

type udpPairHandle struct {
	manager *flowPairManager
	key     pairKey
	record  *udpPairRecord
}

// pairedUDP is a completed asymmetric UDP flow ready for routing.
type pairedUDP struct {
	FlowID       uint64
	Target       string
	Uplink       udpUplink
	Downlink     udpDownlink
	compactLease *compactGenerationLease
	IdleTimeout  time.Duration
}

type udpPairCloseAction struct {
	conn     *pairedUDPConn
	paired   *pairedUDP
	open     udpHalf
	attach   udpHalf
	onFinish func(error)
}

func (a udpPairCloseAction) close(cause error) {
	if a.onFinish != nil {
		a.onFinish(cause)
	}
	if a.conn != nil {
		a.conn.closeFromManager(cause)
		return
	}
	if a.paired != nil {
		closeUDPHalfWithError(udpHalf{Uplink: a.paired.Uplink, Downlink: a.paired.Downlink}, cause)
		if a.paired.compactLease != nil {
			a.paired.compactLease.MarkCleanupDone()
		}
		return
	}
	closeUDPHalfWithError(a.open, cause)
	closeUDPHalfWithError(a.attach, cause)
	lease := a.open.compactLease
	if lease == nil {
		lease = a.attach.compactLease
	}
	if lease != nil {
		lease.MarkCleanupDone()
	}
}

// SubmitUDP caches or pairs a UDP half. On success the manager owns the
// submitted half; on error the caller retains ownership of that half. The first
// half returns a handle, and the completing half additionally returns pairedUDP.
func (m *flowPairManager) SubmitUDP(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target string, half udpHalf) (*udpPairHandle, *pairedUDP, error) {
	return m.SubmitUDPWithSource(ctx, sessionID, header, target, half, nil, udpHalfTransport(header, half))
}

// SubmitUDPWithSource is SubmitUDP with source/transport diagnostics.
func (m *flowPairManager) SubmitUDPWithSource(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target string, half udpHalf, source net.Addr, transport string) (*udpPairHandle, *pairedUDP, error) {
	return m.submitUDPWithSource(ctx, sessionID, header, target, half, source, transport, false)
}

func (m *flowPairManager) stageUDPWithSource(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target string, half udpHalf, source net.Addr, transport string) (*udpPairHandle, error) {
	handle, _, err := m.submitUDPWithSource(ctx, sessionID, header, target, half, source, transport, true)
	return handle, err
}

func (m *flowPairManager) submitUDPWithSource(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target string, half udpHalf, source net.Addr, transport string, staged bool) (*udpPairHandle, *pairedUDP, error) {
	if err := validatePairHeader(header, wire.FlowKindUDP); err != nil {
		return nil, nil, err
	}
	if err := validateUDPHalf(header, half); err != nil {
		return nil, nil, err
	}
	if transport == "" {
		transport = udpHalfTransport(header, half)
	}
	key := pairKey{session: sessionID, flowID: header.FlowID}
	meta := metadataFrom(header, target)
	arriving := &pendingFlow{
		meta: meta, role: half.Role, transport: transport, started: time.Now(),
		sessionID: sessionID, flowID: header.FlowID, source: source,
	}

	m.mu.Lock()
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			m.mu.Unlock()
			return nil, nil, err
		}
	}
	if m.closed {
		m.mu.Unlock()
		return nil, nil, ErrClosed
	}
	if tcp := m.pending[key]; tcp != nil {
		err := fmt.Errorf("%w: flow=%d", ErrCarrierMismatch, key.flowID)
		m.failExistingLocked(key, tcp, err)
		m.mu.Unlock()
		closePendingFlowWithError(tcp, err)
		return nil, nil, err
	}
	if record := m.udpRecords[key]; record != nil {
		handle := record.handle
		if record.phase != udpPairWaiting || record.waitingRole == half.Role {
			err := fmt.Errorf("%w: flow=%d role=%d", ErrDuplicateHalf, key.flowID, half.Role)
			action, waiting := m.finishUDPRecordLocked(handle, err)
			m.mu.Unlock()
			if waiting != nil {
				m.emitPair(ctx, waiting, "pair_cancel", err)
			}
			action.close(err)
			return nil, nil, err
		}
		if !record.meta.equal(meta) {
			err := fmt.Errorf("%w: flow=%d", ErrCarrierMismatch, key.flowID)
			action, waiting := m.finishUDPRecordLocked(handle, err)
			m.mu.Unlock()
			if waiting != nil {
				m.emitPair(ctx, waiting, "pair_cancel", err)
			}
			action.close(err)
			return nil, nil, err
		}
		if record.timer != nil {
			record.timer.Stop()
		}
		m.releaseUDPWaitingLocked(key)
		if half.Role == wire.FlowRoleOpen {
			record.open = half
		} else {
			record.attach = half
		}
		lease := record.open.compactLease
		if lease == nil {
			lease = record.attach.compactLease
		}
		paired := &pairedUDP{
			FlowID:       key.flowID,
			Target:       record.meta.target,
			Uplink:       record.open.Uplink,
			Downlink:     record.attach.Downlink,
			compactLease: lease,
		}
		record.paired = paired
		record.phase = udpPairPaired
		record.staged = record.staged || staged
		waiting := record.pendingView()
		holdPair := record.staged
		m.mu.Unlock()
		m.emitPairSuccess(ctx, waiting, arriving)
		m.watchUDPContext(ctx, handle)
		if holdPair {
			return handle, nil, nil
		}
		return handle, paired, nil
	}
	if len(m.pending)+m.udpWaiting >= m.maxGlobal || m.perSession[key.session] >= m.maxPerSession {
		m.mu.Unlock()
		return nil, nil, fmt.Errorf("%w: session=%x", ErrPairLimit, key.session)
	}
	record := &udpPairRecord{
		meta: meta, waitingRole: half.Role, transport: transport,
		done: make(chan struct{}), phase: udpPairWaiting, staged: staged, started: arriving.started,
		sessionID: sessionID, flowID: header.FlowID, source: source,
	}
	if half.Role == wire.FlowRoleOpen {
		record.open = half
	} else {
		record.attach = half
	}
	handle := &udpPairHandle{manager: m, key: key, record: record}
	record.handle = handle
	record.timer = time.AfterFunc(m.timeout, func() { m.timeoutUDP(handle) })
	m.udpRecords[key] = record
	m.udpWaiting++
	m.perSession[key.session]++
	waiting := record.pendingView()
	m.mu.Unlock()
	m.emitPair(ctx, waiting, "pair_wait", nil)
	m.watchUDPContext(ctx, handle)
	return handle, nil, nil
}

func (m *flowPairManager) admitUDP(handle *udpPairHandle) (*pairedUDP, bool) {
	if m == nil || handle == nil || handle.record == nil {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.udpRecords[handle.key]
	if current == nil || current != handle.record || !current.staged {
		return nil, false
	}
	if current.phase != udpPairWaiting && current.phase != udpPairPaired {
		return nil, false
	}
	current.staged = false
	if current.phase == udpPairPaired {
		return current.paired, true
	}
	return nil, true
}

func validateUDPHalf(header wire.FlowHeader, half udpHalf) error {
	if half.Role != header.Role {
		return fmt.Errorf("%w: UDP half role mismatch", ErrUnsupportedFlow)
	}
	switch half.Role {
	case wire.FlowRoleOpen:
		if half.Uplink == nil {
			return fmt.Errorf("%w: nil UDP uplink", ErrInvalidHandler)
		}
	case wire.FlowRoleAttach:
		if half.Downlink == nil {
			return fmt.Errorf("%w: nil UDP downlink", ErrInvalidHandler)
		}
	default:
		return fmt.Errorf("%w: invalid UDP role", ErrUnsupportedFlow)
	}
	return nil
}

func (m *flowPairManager) watchUDPContext(ctx context.Context, handle *udpPairHandle) {
	if ctx == nil || ctx.Done() == nil || handle == nil {
		return
	}
	go func() {
		select {
		case <-ctx.Done():
			m.finishUDPWithCode(handle, ctx.Err(), "pair_cancel")
		case <-handle.Done():
		}
	}()
}

func (m *flowPairManager) setUDPFinish(handle *udpPairHandle, onFinish func(error)) bool {
	if m == nil || handle == nil || handle.record == nil || onFinish == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.udpRecords[handle.key]
	if current == nil || current != handle.record || current.phase == udpPairClosed || current.onFinish != nil {
		return false
	}
	current.onFinish = onFinish
	return true
}

func (m *flowPairManager) bindUDP(handle *udpPairHandle, conn *pairedUDPConn) bool {
	if handle == nil || handle.record == nil || conn == nil {
		if conn != nil {
			conn.closeFromManager(ErrClosed)
		}
		return false
	}
	m.mu.Lock()
	current := m.udpRecords[handle.key]
	if current == handle.record && current.phase == udpPairPaired {
		if conn.bindToManager() {
			current.active = conn
			current.phase = udpPairActive
			conn.startIdle()
			m.mu.Unlock()
			return true
		}
		action, _ := m.finishUDPRecordLocked(handle, ErrClosed)
		m.mu.Unlock()
		action.close(ErrClosed)
		conn.closeFromManager(ErrClosed)
		return false
	}
	cause := handle.record.err
	m.mu.Unlock()
	if cause == nil {
		cause = ErrClosed
	}
	conn.closeFromManager(cause)
	return false
}

func (m *flowPairManager) cancelUDP(sessionID wire.SessionID, flowID uint64, cause error) {
	key := pairKey{session: sessionID, flowID: flowID}
	m.mu.Lock()
	record := m.udpRecords[key]
	m.mu.Unlock()
	if record == nil {
		return
	}
	m.finishUDPWithCode(&udpPairHandle{manager: m, key: key, record: record}, cause, "pair_cancel")
}

func (m *flowPairManager) cancelUDPSession(sessionID wire.SessionID, cause error) {
	m.mu.Lock()
	handles := make([]*udpPairHandle, 0)
	for key, record := range m.udpRecords {
		if key.session == sessionID {
			handles = append(handles, &udpPairHandle{manager: m, key: key, record: record})
		}
	}
	m.mu.Unlock()
	for _, handle := range handles {
		m.finishUDPWithCode(handle, cause, "pair_cancel")
	}
}

func (m *flowPairManager) finishUDP(handle *udpPairHandle, cause error) {
	m.finishUDPWithCode(handle, cause, "")
}

func (m *flowPairManager) finishUDPWithCode(handle *udpPairHandle, cause error, code string) {
	if m == nil || handle == nil || handle.record == nil {
		return
	}
	m.mu.Lock()
	action, pending := m.finishUDPRecordLocked(handle, cause)
	m.mu.Unlock()
	if pending == nil {
		return
	}
	if code != "" {
		m.emitPair(context.Background(), pending, code, cause)
	}
	action.close(cause)
}

func (m *flowPairManager) finishUDPRecordLocked(handle *udpPairHandle, cause error) (udpPairCloseAction, *pendingFlow) {
	current := m.udpRecords[handle.key]
	if current == nil || current != handle.record || current.phase == udpPairClosed {
		return udpPairCloseAction{}, nil
	}
	pending := current.pendingView()
	if current.phase == udpPairWaiting {
		m.releaseUDPWaitingLocked(handle.key)
	}
	if current.timer != nil {
		current.timer.Stop()
	}
	delete(m.udpRecords, handle.key)
	current.phase = udpPairClosed
	current.err = cause
	close(current.done)
	action := udpPairCloseAction{open: current.open, attach: current.attach, onFinish: current.onFinish}
	if current.active != nil {
		action = udpPairCloseAction{conn: current.active, onFinish: current.onFinish}
	} else if current.paired != nil {
		action = udpPairCloseAction{paired: current.paired, onFinish: current.onFinish}
	}
	return action, pending
}

func (m *flowPairManager) timeoutUDP(handle *udpPairHandle) {
	if handle == nil {
		return
	}
	err := fmt.Errorf("%w: flow=%d", ErrPairTimeout, handle.key.flowID)
	m.finishUDPWithCode(handle, err, "pair_timeout")
}

func (m *flowPairManager) releaseUDPWaitingLocked(key pairKey) {
	if m.udpWaiting > 0 {
		m.udpWaiting--
	}
	if count := m.perSession[key.session]; count <= 1 {
		delete(m.perSession, key.session)
	} else {
		m.perSession[key.session] = count - 1
	}
}

func (r *udpPairRecord) pendingView() *pendingFlow {
	if r == nil {
		return nil
	}
	return &pendingFlow{
		meta: r.meta, role: r.waitingRole, transport: r.transport,
		state: pairWaiting, err: r.err, started: r.started,
		sessionID: r.sessionID, flowID: r.flowID, source: r.source,
	}
}

func (h *udpPairHandle) Deliver(payload []byte) bool {
	if h == nil || h.manager == nil || h.record == nil {
		return false
	}
	h.manager.mu.Lock()
	current := h.manager.udpRecords[h.key]
	if current == nil || current != h.record || current.phase == udpPairClosed {
		h.manager.mu.Unlock()
		return false
	}
	uplink := current.open.Uplink
	h.manager.mu.Unlock()
	deliverer, ok := uplink.(interface{ Deliver([]byte) })
	if !ok {
		return false
	}
	deliverer.Deliver(payload)
	return true
}

func (h *udpPairHandle) Done() <-chan struct{} {
	if h == nil || h.record == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return h.record.done
}

func (h *udpPairHandle) Err() error {
	if h == nil || h.manager == nil || h.record == nil {
		return ErrClosed
	}
	h.manager.mu.Lock()
	defer h.manager.mu.Unlock()
	return h.record.err
}
