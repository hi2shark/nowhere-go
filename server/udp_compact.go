package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

var (
	errCompactFlowRejected = errors.New("nowhere: compact flow rejected")
	errCompactAckRevoked   = errors.New("nowhere: compact generation revoked")
)

// compactGenerationLease owns every outbound QUIC DATAGRAM admitted for one
// Compact flow generation. A retiring generation remains published until all
// admitted sends, physical cleanup, and any required terminal CLOSE complete.
type compactGenerationLease struct {
	flowID uint64
	send   func([]byte) error

	mu               sync.Mutex
	generation       uint64
	active           bool
	retiring         bool
	acked            bool
	inFlight         int
	cleanupDone      bool
	terminalRequired bool
	terminalStarted  bool
	terminalDone     bool
	onFinalized      func()
	finalized        bool
}

func (l *compactGenerationLease) bind(generation uint64) bool {
	return l.bindWithFinalizer(generation, nil)
}

func (l *compactGenerationLease) bindWithFinalizer(generation uint64, onFinalized func()) bool {
	if l == nil || generation == 0 || l.flowID == 0 || l.send == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.generation != 0 {
		return false
	}
	l.generation = generation
	l.active = true
	l.terminalDone = true
	l.onFinalized = onFinalized
	return true
}

func (l *compactGenerationLease) Retire(generation uint64, terminalRequired bool) bool {
	if l == nil || generation == 0 {
		return false
	}
	var onFinalized func()
	l.mu.Lock()
	if l.generation != generation || l.retiring || l.finalized {
		l.mu.Unlock()
		return false
	}
	l.active = false
	l.retiring = true
	l.terminalRequired = terminalRequired
	l.terminalDone = !terminalRequired
	onFinalized = l.finalizeCallbackLocked()
	l.mu.Unlock()
	if onFinalized != nil {
		onFinalized()
	}
	return true
}

func (l *compactGenerationLease) Abort(generation uint64) {
	if l == nil || generation == 0 {
		return
	}
	l.mu.Lock()
	if l.generation == generation {
		l.active = false
		l.retiring = true
		l.cleanupDone = true
		l.terminalRequired = false
		l.terminalDone = true
		l.finalized = true
	}
	l.mu.Unlock()
}

func (l *compactGenerationLease) MarkCleanupDone() {
	if l == nil {
		return
	}
	var onFinalized func()
	l.mu.Lock()
	if !l.finalized {
		l.cleanupDone = true
		onFinalized = l.finalizeCallbackLocked()
	}
	l.mu.Unlock()
	if onFinalized != nil {
		onFinalized()
	}
}

func (l *compactGenerationLease) finalizeCallbackLocked() func() {
	if !l.retiring || l.inFlight != 0 || !l.cleanupDone || !l.terminalDone || l.finalized {
		return nil
	}
	l.finalized = true
	return l.onFinalized
}

func (l *compactGenerationLease) sendNormal(frame []byte, markAck bool) error {
	if l == nil || l.flowID == 0 || l.send == nil {
		return fmt.Errorf("%w: invalid Compact generation lease", ErrInvalidHandler)
	}
	l.mu.Lock()
	if !l.active || l.retiring {
		l.mu.Unlock()
		return errCompactAckRevoked
	}
	l.inFlight++
	l.mu.Unlock()

	sendErr := l.send(frame)

	var onFinalized func()
	l.mu.Lock()
	l.inFlight--
	var result error
	if !l.active || l.retiring {
		result = errCompactAckRevoked
	} else if sendErr != nil {
		result = sendErr
	} else {
		if markAck {
			l.acked = true
		}
		result = nil
	}
	onFinalized = l.finalizeCallbackLocked()
	l.mu.Unlock()
	if onFinalized != nil {
		onFinalized()
	}
	return result
}

func (l *compactGenerationLease) SendOpenAck() error {
	if l == nil {
		return fmt.Errorf("%w: invalid Compact generation lease", ErrInvalidHandler)
	}
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeOpenAck, l.flowID, nil)
	if err != nil {
		return err
	}
	return l.sendNormal(frame, true)
}

func (l *compactGenerationLease) SendData(payload []byte) error {
	if l == nil {
		return fmt.Errorf("%w: invalid Compact generation lease", ErrInvalidHandler)
	}
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeData, l.flowID, payload)
	if err != nil {
		return err
	}
	return l.sendNormal(frame, false)
}

func (l *compactGenerationLease) SendTerminalClose() error {
	if l == nil || l.flowID == 0 || l.send == nil {
		return fmt.Errorf("%w: invalid Compact generation lease", ErrInvalidHandler)
	}
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeCompactClose, l.flowID, nil)
	if err != nil {
		return err
	}
	l.mu.Lock()
	if !l.retiring {
		l.mu.Unlock()
		return errCompactAckRevoked
	}
	if !l.terminalRequired || l.terminalStarted {
		l.mu.Unlock()
		return nil
	}
	l.terminalStarted = true
	l.terminalDone = false
	l.inFlight++
	l.mu.Unlock()

	sendErr := l.send(frame)

	var onFinalized func()
	l.mu.Lock()
	l.inFlight--
	l.terminalDone = true
	onFinalized = l.finalizeCallbackLocked()
	l.mu.Unlock()
	if onFinalized != nil {
		onFinalized()
	}
	return sendErr
}

func (l *compactGenerationLease) Acked() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active && !l.retiring && l.acked
}

func (e *compactUDPEntry) matches(frame wire.CompactUDPFrame) bool {
	return e != nil && frame.Type == wire.UDPTypeOpenData && e.flowID == frame.FlowID && e.target == frame.Target && e.downlink == frame.Downlink
}

func (e *compactUDPEntry) deliver(payload []byte) bool {
	if e == nil {
		return false
	}
	if e.symmetric != nil {
		return e.symmetric.deliver(payload)
	}
	if e.pair != nil {
		return e.pair.Deliver(payload)
	}
	return false
}

func (s *portalSession) handleCompactFrame(ctx context.Context, frame wire.CompactUDPFrame) {
	switch frame.Type {
	case wire.UDPTypeOpenData:
		s.handleOpenData(ctx, frame)
	case wire.UDPTypeData:
		entry, state := s.lookupCompactEntry(frame.FlowID)
		switch state {
		case compactEntryRetiring:
			return
		case compactEntryAbsent:
			s.sendCompactClose(frame.FlowID)
			return
		}
		if !entry.deliver(frame.Payload) {
			s.finishCompactEntry(entry, errCompactFlowRejected, true)
		}
	case wire.UDPTypeCompactClose:
		if entry, state := s.lookupCompactEntry(frame.FlowID); state == compactEntryActive {
			s.finishCompactEntry(entry, io.EOF, false)
		}
	}
}

func (s *portalSession) handleOpenData(ctx context.Context, frame wire.CompactUDPFrame) {
	entry, state := s.lookupCompactEntry(frame.FlowID)
	if state == compactEntryRetiring {
		return
	}
	if state == compactEntryActive {
		if !entry.matches(frame) {
			s.finishCompactEntry(entry, errCompactFlowRejected, true)
			return
		}
		if !entry.deliver(frame.Payload) {
			s.finishCompactEntry(entry, errCompactFlowRejected, true)
			return
		}
		if entry.lease != nil && entry.lease.Acked() {
			if err := entry.lease.SendOpenAck(); err != nil && !errors.Is(err, errCompactAckRevoked) {
				s.finishCompactEntry(entry, err, true)
			}
		}
		return
	}

	if frame.Downlink == wire.CarrierUDP {
		s.openSymmetricCompact(ctx, frame)
		return
	}
	s.openAsymmetricCompact(ctx, frame)
}

func (s *portalSession) openSymmetricCompact(ctx context.Context, frame wire.CompactUDPFrame) {
	flow := newCompactUDPFlow(s, frame.FlowID, frame.Target, frame.Downlink)
	entry := &compactUDPEntry{
		flowID:    frame.FlowID,
		target:    frame.Target,
		downlink:  frame.Downlink,
		lease:     &compactGenerationLease{flowID: frame.FlowID, send: s.SendDatagram},
		symmetric: flow,
	}
	if !s.reserveCompactEntry(entry) {
		flow.shutdown(errCompactFlowRejected)
		s.sendCompactClose(frame.FlowID)
		return
	}
	if !entry.deliver(frame.Payload) {
		s.finishCompactEntry(entry, errCompactFlowRejected, true)
		return
	}
	if err := entry.lease.SendOpenAck(); err != nil {
		if !errors.Is(err, errCompactAckRevoked) {
			s.finishCompactEntry(entry, err, true)
		}
		return
	}
	flow.routedOnce.Do(func() {
		flowCtx := ContextWithCloseHandler(ctx, flow.closeWithError)
		go func() { _ = s.Handler.routePacket(flowCtx, flow, s.Source, frame.Target) }()
	})
}

func (s *portalSession) openAsymmetricCompact(ctx context.Context, frame wire.CompactUDPFrame) {
	lease := &compactGenerationLease{flowID: frame.FlowID, send: s.SendDatagram}
	uplink := newQUICUDPUplink(s)
	header := wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		FlowID:   frame.FlowID,
		Kind:     wire.FlowKindUDP,
		Uplink:   wire.CarrierUDP,
		Downlink: frame.Downlink,
	}
	half := udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink, compactLease: lease}
	handle, err := s.Handler.pairing.stageUDPWithSource(ctx, s.ID, header, frame.Target, half, s.Source, udpHalfTransport(header, half))
	if err != nil {
		closeUDPHalfWithError(half, err)
		s.sendCompactClose(frame.FlowID)
		return
	}
	entry := &compactUDPEntry{
		flowID:   frame.FlowID,
		target:   frame.Target,
		downlink: frame.Downlink,
		lease:    lease,
		pair:     handle,
	}
	if !s.reserveCompactEntry(entry) {
		s.Handler.pairing.finishUDP(handle, errCompactFlowRejected)
		s.sendCompactClose(frame.FlowID)
		return
	}
	if !s.Handler.pairing.setUDPFinish(handle, func(cause error) {
		s.finishCompactEntry(entry, cause, true)
	}) {
		s.finishCompactEntry(entry, handle.Err(), true)
		return
	}
	if !entry.deliver(frame.Payload) {
		s.finishCompactEntry(entry, errCompactFlowRejected, true)
		return
	}
	paired, ok := s.Handler.pairing.admitUDP(handle)
	if !ok {
		s.finishCompactEntry(entry, handle.Err(), true)
		return
	}
	if paired != nil {
		go s.routeCompactPair(ctx, handle, paired, frame.Target)
	}
}

func (s *portalSession) routeCompactPair(ctx context.Context, handle *udpPairHandle, paired *pairedUDP, target string) {
	paired.IdleTimeout = s.Handler.config.timeouts.UDPIdle
	conn := newPairedUDPConn(paired)
	conn.setFinish(func(cause error) { s.Handler.pairing.finishUDP(handle, cause) })
	if !s.Handler.pairing.bindUDP(handle, conn) {
		return
	}
	_ = s.Handler.routePacket(ctx, conn, s.Source, target)
}

func (s *portalSession) finishCompactEntry(entry *compactUDPEntry, cause error, sendClose bool) {
	if entry == nil {
		return
	}
	detached, ok := s.retireCompactEntry(entry.flowID, entry.generation, sendClose)
	if !ok {
		return
	}
	if detached.symmetric != nil {
		detached.symmetric.shutdown(cause)
	}
	if detached.pair != nil && s.Handler != nil && s.Handler.pairing != nil {
		s.Handler.pairing.finishUDP(detached.pair, cause)
	}
	if detached.symmetric == nil && detached.pair == nil && detached.lease != nil {
		detached.lease.MarkCleanupDone()
	}
	if detached.lease != nil {
		_ = detached.lease.SendTerminalClose()
	}
}

func (s *portalSession) sendCompactClose(flowID uint64) {
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeCompactClose, flowID, nil)
	if err == nil {
		_ = s.SendDatagram(frame)
	}
}

// compactUDPFlow adapts a symmetric Compact flow to net.PacketConn.
type compactUDPFlow struct {
	session    *portalSession
	flowID     uint64
	generation uint64
	lease      *compactGenerationLease
	target     string
	downlink   wire.Carrier
	dest       net.Addr
	waiter     chan []byte
	done       chan struct{}
	mu         sync.Mutex
	closed     bool
	closeErr   error
	closeOnce  sync.Once
	routedOnce sync.Once
	readDL     deadlineState
	writeDL    deadlineState
	idle       *time.Timer
}

func newCompactUDPFlow(session *portalSession, flowID uint64, target string, downlink wire.Carrier) *compactUDPFlow {
	return &compactUDPFlow{
		session:  session,
		flowID:   flowID,
		target:   target,
		downlink: downlink,
		dest:     parseTargetAddr(target),
		waiter:   make(chan []byte, session.Handler.config.limits.QUICQueuePackets),
		done:     make(chan struct{}),
	}
}

func (f *compactUDPFlow) deliver(payload []byte) bool {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return false
	}
	f.mu.Unlock()
	if !f.session.reserveQueueBytes(len(payload)) {
		return true
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		f.session.releaseQueueBytes(len(payload))
		return false
	}
	copyPayload := append([]byte(nil), payload...)
	select {
	case f.waiter <- copyPayload:
		f.mu.Unlock()
		f.resetIdle()
	default:
		f.mu.Unlock()
		f.session.releaseQueueBytes(len(copyPayload))
	}
	return true
}

func (f *compactUDPFlow) shutdown(err error) {
	if f.session != nil && f.generation != 0 {
		f.session.retireCompactEntry(f.flowID, f.generation, false)
	}
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.closeErr = err
		if f.idle != nil {
			f.idle.Stop()
		}
		f.mu.Unlock()
		close(f.done)
		for {
			select {
			case payload := <-f.waiter:
				f.session.releaseQueueBytes(len(payload))
			default:
				return
			}
		}
	})
	if f.lease != nil {
		f.lease.MarkCleanupDone()
	}
}

func (f *compactUDPFlow) closeWithError(err error) {
	f.session.finishCompactEntry(&compactUDPEntry{flowID: f.flowID, generation: f.generation}, err, true)
	f.shutdown(err)
}

func (f *compactUDPFlow) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		wait, expired := f.readDL.newReadWait(time.Now())
		if expired {
			return 0, nil, deadlineError()
		}
		select {
		case payload := <-f.waiter:
			wait.stop()
			f.session.releaseQueueBytes(len(payload))
			f.resetIdle()
			n = copy(p, payload)
			return n, f.dest, nil
		case <-f.done:
			wait.stop()
			return 0, nil, f.err()
		case <-wait.changed:
			wait.stop()
		case <-wait.timerC:
			if wait.timerExpired(time.Now()) {
				return 0, nil, deadlineError()
			}
		}
	}
}

func (f *compactUDPFlow) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case <-f.done:
		return 0, f.err()
	default:
	}
	if f.writeDL.expired(time.Now()) {
		return 0, deadlineError()
	}
	if f.lease == nil {
		return 0, fmt.Errorf("%w: Compact flow has no generation lease", ErrInvalidHandler)
	}
	if err := f.lease.SendData(p); err != nil {
		return 0, err
	}
	f.resetIdle()
	return len(p), nil
}

func (f *compactUDPFlow) Close() error {
	f.closeWithError(net.ErrClosed)
	return nil
}

func (f *compactUDPFlow) LocalAddr() net.Addr {
	if s := f.session; s != nil && s.Conn != nil {
		return s.Conn.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (f *compactUDPFlow) SetDeadline(value time.Time) error {
	f.readDL.set(value)
	f.writeDL.set(value)
	return nil
}

func (f *compactUDPFlow) SetReadDeadline(value time.Time) error {
	f.readDL.set(value)
	return nil
}

func (f *compactUDPFlow) SetWriteDeadline(value time.Time) error {
	f.writeDL.set(value)
	return nil
}

func (f *compactUDPFlow) resetIdle() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	if f.idle != nil {
		f.idle.Stop()
	}
	timeout := f.session.Handler.config.timeouts.UDPIdle
	f.idle = time.AfterFunc(timeout, func() { f.shutdown(context.DeadlineExceeded) })
	f.mu.Unlock()
}

func (f *compactUDPFlow) err() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closeErr != nil {
		return f.closeErr
	}
	return io.EOF
}

var _ net.PacketConn = (*compactUDPFlow)(nil)
