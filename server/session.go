package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hi2shark/nowhere-go/diagnostic"
	"github.com/hi2shark/nowhere-go/wire"
)

const (
	preAuthDatagramBudget         = 64 * 1024
	preactivationControlLimit     = 64
	preactivationDatagramLimit    = 64
	preactivationByteLimit        = 64 * 1024
	preactivationFramesPerControl = 16
	preactivationBytesPerControl  = 16 * 1024
	preactivationTTL              = 10 * time.Second
)

type reassemblyTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type realReassemblyTicker struct {
	*time.Ticker
}

func (t *realReassemblyTicker) Chan() <-chan time.Time { return t.C }

// sessionManager tracks authenticated QUIC sessions by Nowhere session_id.
// A newer connection with the same session_id replaces the previous one.
type sessionManager struct {
	mu                  sync.Mutex
	sessions            map[wire.SessionID]*portalSession
	claims              *claimRegistry
	nextGeneration      uint64
	generationExhausted bool
	max                 int
	closed              bool
}

func newSessionManager(registries ...*claimRegistry) *sessionManager {
	var claims *claimRegistry
	if len(registries) > 0 {
		claims = registries[0]
	}
	return &sessionManager{sessions: make(map[wire.SessionID]*portalSession), claims: claims, max: DefaultActiveQUICSessions}
}

func (m *sessionManager) configureLimit(max int) {
	m.mu.Lock()
	m.max = max
	m.mu.Unlock()
}

func (m *sessionManager) Current(sessionID wire.SessionID) *portalSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[sessionID]
}

func (m *sessionManager) Register(session *portalSession) error {
	if m == nil || session == nil {
		return fmt.Errorf("%w: nil session", ErrInvalidHandler)
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	old := m.sessions[session.ID]
	if old == session {
		m.mu.Unlock()
		return nil
	}
	if old == nil && len(m.sessions) >= m.max {
		m.mu.Unlock()
		return ErrSessionLimit
	}
	var cleanup *sessionReplacementCleanup
	if m.claims != nil {
		session.Generation, cleanup = m.claims.beginSessionRegistration(session.ID, old != nil, markForcedTermination(ErrClosed))
	} else {
		if m.generationExhausted || m.nextGeneration == ^uint64(0) {
			m.generationExhausted = true
			m.mu.Unlock()
			return fmt.Errorf("%w: session generation exhausted", ErrSessionLimit)
		}
		m.nextGeneration++
		session.Generation = m.nextGeneration
	}
	m.sessions[session.ID] = session
	m.mu.Unlock()

	if old != nil {
		if m.claims != nil {
			m.claims.unregisterSessionGeneration(old.ID, old.Generation)
		}
		old.Close()
	}
	cleanup.run()
	return nil
}

func (m *sessionManager) Unregister(session *portalSession) {
	if m == nil || session == nil {
		return
	}
	m.mu.Lock()
	if cur, ok := m.sessions[session.ID]; ok && cur == session {
		delete(m.sessions, session.ID)
	}
	m.mu.Unlock()
	if m.claims != nil {
		m.claims.unregisterSessionGeneration(session.ID, session.Generation)
	}
}

func (m *sessionManager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	sessions := make([]*portalSession, 0, len(m.sessions))
	for id, session := range m.sessions {
		sessions = append(sessions, session)
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	for _, session := range sessions {
		if m.claims != nil {
			m.claims.unregisterSessionGeneration(session.ID, session.Generation)
		}
		session.Close()
	}
}

// portalSession is one authenticated QUIC connection (via QuicConn).
type pendingUDPControl struct {
	created time.Time
	frames  []wire.UDPFrame
	bytes   int
}

type portalSession struct {
	ID         wire.SessionID
	Generation uint64
	Conn       QuicConn
	Handler    *Handler
	Source     net.Addr

	cancel context.CancelCauseFunc

	mu              sync.Mutex
	flows           map[uint64]*nowuFlow
	pendingControls map[uint64]*pendingUDPControl
	pendingFrames   int
	pendingBytes    int
	queuedBytes     int
	budget          *byteBudget
	reassembler     *udpReassembler
	expiryCancel    context.CancelFunc
	expiryDone      chan struct{}
	closeDone       chan struct{}
	closed          bool
	transportOnce   sync.Once
}

func newPortalSession(id wire.SessionID, conn QuicConn, handler *Handler, source net.Addr) *portalSession {
	queueBytes := DefaultUDPQueueBytes
	if handler != nil && handler.config != nil {
		queueBytes = handler.config.limits.UDPQueueBytes
	}
	budget := &byteBudget{limit: queueBytes}
	return &portalSession{
		ID:              id,
		Conn:            conn,
		Handler:         handler,
		Source:          source,
		flows:           make(map[uint64]*nowuFlow),
		pendingControls: make(map[uint64]*pendingUDPControl),
		budget:          budget,
		reassembler:     newUDPReassembler(nowuPartialLimit, nowuPartialTTL, budget),
	}
}

func (s *portalSession) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closeDone != nil {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		return
	}
	done := make(chan struct{})
	s.closeDone = done
	s.closed = true
	flows := s.flows
	s.flows = nil
	s.pendingControls = nil
	s.pendingFrames = 0
	s.pendingBytes = 0
	cancel := s.cancel
	expiryCancel := s.expiryCancel
	expiryDone := s.expiryDone
	s.mu.Unlock()

	cause := markForcedTermination(ErrClosed)
	if cancel != nil {
		cancel(cause)
	}
	if expiryCancel != nil {
		expiryCancel()
	}
	if expiryDone != nil {
		<-expiryDone
	}
	for _, f := range flows {
		f.shutdown(cause)
	}
	if s.reassembler != nil {
		s.reassembler.Close()
	}
	s.closeTransport(cause)
	close(done)
}

func (s *portalSession) closeTransport(error) {
	if s == nil {
		return
	}
	s.transportOnce.Do(func() {
		if s.Conn != nil {
			_ = s.Conn.CloseWithError(uint64(wire.CloseErrCodeOK), "")
		}
	})
}

func (s *portalSession) startReassemblyExpiry() {
	if s == nil || s.Handler == nil || s.Handler.newReassemblyTicker == nil || s.reassembler == nil {
		return
	}
	ticker := s.Handler.newReassemblyTicker(nowuPartialTTL / 2)
	if ticker == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.mu.Lock()
	if s.closed || s.expiryCancel != nil {
		s.mu.Unlock()
		cancel()
		ticker.Stop()
		return
	}
	s.expiryCancel = cancel
	s.expiryDone = done
	s.mu.Unlock()
	go func() {
		defer close(done)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.Chan():
				now := time.Now()
				if s.Handler.now != nil {
					now = s.Handler.now()
				}
				s.reassembler.Expire(now)
				s.expirePendingControls(now)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *portalSession) SendDatagram(b []byte) error {
	return s.Conn.SendDatagram(b)
}

func (s *portalSession) maxDatagramSize() int {
	if s != nil && s.Conn != nil {
		if provider, ok := s.Conn.(interface{ CurrentMaxDatagramSize() int }); ok {
			if size := provider.CurrentMaxDatagramSize(); size > nowuDataHeaderLen {
				return size
			}
		}
	}
	return 1200
}

func (s *portalSession) getFlow(id uint64) *nowuFlow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flows[id]
}

type flowInsertResult uint8

const (
	flowInserted flowInsertResult = iota
	flowDuplicate
	flowSessionClosed
)

func (s *portalSession) insertFlow(id uint64, flow *nowuFlow) flowInsertResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return flowSessionClosed
	}
	if _, exists := s.flows[id]; exists {
		return flowDuplicate
	}
	s.flows[id] = flow
	return flowInserted
}

func (s *portalSession) putFlow(id uint64, flow *nowuFlow) bool {
	flow.ownsReassembly.Store(true)
	if s.insertFlow(id, flow) == flowInserted {
		return true
	}
	flow.ownsReassembly.Store(false)
	return false
}

func (s *portalSession) removeFlow(id uint64, flow *nowuFlow) {
	s.mu.Lock()
	if current := s.flows[id]; current == flow {
		delete(s.flows, id)
	}
	s.mu.Unlock()
}

func (s *portalSession) beginPendingUDPControl(header wire.FlowHeader) (*pendingUDPControl, error) {
	if err := validateFlowTransport(header, wire.CarrierUDP); err != nil {
		return nil, err
	}
	if header.Role == wire.FlowRoleAttach {
		return nil, nil
	}
	if header.Role != wire.FlowRoleOpen && header.Role != wire.FlowRoleDuplex {
		return nil, fmt.Errorf("%w: invalid UDP flow role", ErrUnsupportedFlow)
	}
	now := time.Now()
	if s.Handler != nil && s.Handler.now != nil {
		now = s.Handler.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expirePendingControlsLocked(now)
	if s.closed {
		return nil, ErrClosed
	}
	if s.flows[header.FlowID] != nil || s.pendingControls[header.FlowID] != nil {
		return nil, ErrDuplicateHalf
	}
	if len(s.pendingControls) >= preactivationControlLimit {
		return nil, ErrPairLimit
	}
	pending := &pendingUDPControl{created: now}
	s.pendingControls[header.FlowID] = pending
	return pending, nil
}

func (s *portalSession) cancelPendingUDPControl(flowID uint64, pending *pendingUDPControl) {
	if pending == nil {
		return
	}
	s.mu.Lock()
	if s.pendingControls[flowID] == pending {
		s.removePendingControlLocked(flowID, pending)
	}
	s.mu.Unlock()
}

func (s *portalSession) bufferPendingUDPData(frame wire.UDPFrame, size int) bool {
	now := time.Now()
	if s.Handler != nil && s.Handler.now != nil {
		now = s.Handler.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expirePendingControlsLocked(now)
	pending := s.pendingControls[frame.FlowID]
	if pending == nil {
		return false
	}
	if size < 0 ||
		s.pendingFrames >= preactivationDatagramLimit || s.pendingBytes+size > preactivationByteLimit ||
		len(pending.frames) >= preactivationFramesPerControl || pending.bytes+size > preactivationBytesPerControl {
		return true
	}
	frame.Fragment.Payload = append([]byte(nil), frame.Fragment.Payload...)
	pending.frames = append(pending.frames, frame)
	pending.bytes += size
	s.pendingFrames++
	s.pendingBytes += size
	return true
}

func (s *portalSession) expirePendingControls(now time.Time) {
	s.mu.Lock()
	s.expirePendingControlsLocked(now)
	s.mu.Unlock()
}

func (s *portalSession) expirePendingControlsLocked(now time.Time) {
	for flowID, pending := range s.pendingControls {
		if !now.Before(pending.created.Add(preactivationTTL)) {
			s.removePendingControlLocked(flowID, pending)
		}
	}
}

func (s *portalSession) removePendingControlLocked(flowID uint64, pending *pendingUDPControl) {
	if s.pendingControls[flowID] != pending {
		return
	}
	delete(s.pendingControls, flowID)
	s.pendingFrames -= len(pending.frames)
	s.pendingBytes -= pending.bytes
	if s.pendingFrames < 0 {
		s.pendingFrames = 0
	}
	if s.pendingBytes < 0 {
		s.pendingBytes = 0
	}
	pending.frames = nil
	pending.bytes = 0
}

func (s *portalSession) reserveQueueBytes(count int) bool {
	if s == nil || count < 0 {
		return false
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed || !s.budget.reserve(count) {
		return false
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.budget.release(count)
		return false
	}
	s.queuedBytes += count
	s.mu.Unlock()
	return true
}

func (s *portalSession) releaseQueueBytes(count int) {
	if s == nil || count <= 0 {
		return
	}
	s.mu.Lock()
	s.queuedBytes -= count
	if s.queuedBytes < 0 {
		s.queuedBytes = 0
	}
	s.mu.Unlock()
	s.budget.release(count)
}

// ServeQUIC authenticates and serves one QuicConn until it closes.
func (h *Handler) ServeQUIC(parent context.Context, conn QuicConn) error {
	if err := h.validate(); err != nil {
		if conn != nil {
			_ = conn.CloseWithError(1, "access denied")
		}
		return err
	}
	if conn == nil {
		return fmt.Errorf("%w: nil quic connection", ErrInvalidHandler)
	}
	taskCtx, finish, err := h.tasks.StartTransport(parent, func(error) {
		_ = conn.CloseWithError(uint64(wire.CloseErrCodeOK), "")
	})
	if err != nil {
		_ = conn.CloseWithError(1, "access denied")
		return err
	}
	defer finish()
	source := conn.RemoteAddr()
	guard, ok := h.admission.tryAcquire(source)
	if !ok {
		_ = conn.CloseWithError(1, "access denied")
		h.emitAdmissionLimited(taskCtx, source)
		return report(ErrAdmissionLimit)
	}
	releaseAdmission := guard.Release
	defer releaseAdmission()

	ctx, cancel := context.WithCancelCause(taskCtx)
	defer cancel(nil)

	session, pending, err := h.authenticateQuic(ctx, conn)
	if err != nil {
		_ = conn.CloseWithError(1, "access denied")
		h.emit(ctx, diagnostic.LevelError, "auth_failed", source, "", wire.SessionID{}, 0, err)
		return err
	}
	releaseAdmission()
	session.cancel = cancel
	if err := h.sessions.Register(session); err != nil {
		_ = conn.CloseWithError(1, "access denied")
		return err
	}
	defer h.sessions.Unregister(session)
	defer session.Close()
	session.startReassemblyExpiry()

	h.emit(ctx, diagnostic.LevelInfo, "session_started", source, "", session.ID, 0, nil)
	go session.datagramLoop(ctx, pending)
	session.acceptStreams(ctx)
	return nil
}

func (h *Handler) authenticateQuic(ctx context.Context, conn QuicConn) (*portalSession, [][]byte, error) {
	deadline := h.authDeadline()
	authCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	type authResult struct {
		id  wire.SessionID
		err error
	}
	authCh := make(chan authResult, 1)
	go func() {
		stream, err := conn.AcceptStream(authCtx)
		if err != nil {
			authCh <- authResult{err: err}
			return
		}
		_ = stream.SetReadDeadline(deadline)
		id, err := wire.ReadAuthFrame(stream, h.config.key, h.config.spec)
		if err == nil {
			var trailing [1]byte
			n, tailErr := stream.Read(trailing[:])
			if n != 0 || !errors.Is(tailErr, io.EOF) {
				err = wire.ErrInvalidFrame
			}
		}
		stream.CancelWrite(uint64(wire.CloseErrCodeOK))
		_ = stream.Close()
		authCh <- authResult{id: id, err: err}
	}()

	type dgramResult struct {
		data []byte
		err  error
	}
	dgramCh := make(chan dgramResult, 1)
	dgramDone := make(chan struct{})
	go func() {
		defer close(dgramDone)
		for {
			data, err := conn.ReceiveDatagram(authCtx)
			if err != nil {
				select {
				case dgramCh <- dgramResult{err: err}:
				case <-authCtx.Done():
				}
				return
			}
			cp := make([]byte, len(data))
			copy(cp, data)
			select {
			case dgramCh <- dgramResult{data: cp}:
			case <-authCtx.Done():
				return
			}
		}
	}()

	var pending [][]byte
	pendingBytes := 0
	for {
		select {
		case res := <-authCh:
			cancel()
			<-dgramDone
			for {
				select {
				case d := <-dgramCh:
					if d.err == nil && pendingBytes+len(d.data) <= preAuthDatagramBudget {
						pending = append(pending, d.data)
						pendingBytes += len(d.data)
					}
				default:
					if res.err != nil {
						h.waitAuthFailure(ctx, deadline)
						return nil, nil, res.err
					}
					return newPortalSession(res.id, conn, h, conn.RemoteAddr()), pending, nil
				}
			}
		case d := <-dgramCh:
			if d.err != nil {
				continue
			}
			if pendingBytes+len(d.data) <= preAuthDatagramBudget {
				pending = append(pending, d.data)
				pendingBytes += len(d.data)
			}
		case <-authCtx.Done():
			h.waitAuthFailure(ctx, deadline)
			return nil, nil, authCtx.Err()
		}
	}
}

func (s *portalSession) acceptStreams(ctx context.Context) {
	for {
		stream, err := s.Conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.handleStream(ctx, stream)
	}
}

func (s *portalSession) handleStream(ctx context.Context, stream QuicStream) {
	conn := wrapQuicStream(stream, s.Conn.LocalAddr(), s.Conn.RemoteAddr())
	source := s.Source
	_ = conn.SetReadDeadline(s.Handler.now().Add(s.Handler.config.timeouts.RequestIdle))

	header, err := wire.ReadFlowHeader(conn)
	if err != nil {
		_ = conn.Close()
		s.Handler.emit(ctx, diagnostic.LevelError, "request_read_failed", source, "", s.ID, 0, err)
		return
	}
	target, err := s.Handler.readFlowTarget(conn, header)
	if err != nil {
		s.Handler.rejectFlowSetupGeneration(conn, s.ID, s.Generation, true, header, wire.FlowErrorCodeInvalidRequest)
		_ = conn.Close()
		s.Handler.emit(ctx, diagnostic.LevelError, "request_read_failed", source, "", s.ID, header.FlowID, err)
		return
	}
	var pending *pendingUDPControl
	if header.Kind == wire.FlowKindUDP {
		pending, err = s.beginPendingUDPControl(header)
		if err != nil {
			if errors.Is(err, ErrDuplicateHalf) {
				rejectQUICControl(conn, header, setupFailureCode(err))
			} else {
				s.Handler.rejectFlowSetupGeneration(conn, s.ID, s.Generation, true, header, setupFailureCode(err))
			}
			_ = conn.Close()
			s.Handler.emit(ctx, diagnostic.LevelError, "request_read_failed", source, target, s.ID, header.FlowID, err)
			return
		}
		defer s.cancelPendingUDPControl(header.FlowID, pending)

		// UDP uses a dedicated control stream, so FIN is the setup boundary.
		var trailing [1]byte
		n, tailErr := conn.Read(trailing[:])
		if n != 0 || !errors.Is(tailErr, io.EOF) {
			err = wire.ErrInvalidFrame
			s.Handler.rejectFlowSetupGeneration(conn, s.ID, s.Generation, true, header, wire.FlowErrorCodeInvalidRequest)
			_ = conn.Close()
			s.Handler.emit(ctx, diagnostic.LevelError, "request_read_failed", source, target, s.ID, header.FlowID, err)
			return
		}
	}
	_ = conn.SetDeadline(time.Time{})

	if header.Kind == wire.FlowKindUDP {
		err = s.handleUDPControl(ctx, conn, source, header, target, pending)
	} else {
		err = s.Handler.handleFlowGeneration(ctx, conn, source, s.ID, s.Generation, true, header, target, wire.CarrierUDP)
	}
	if err != nil && !IsReported(err) {
		s.Handler.emit(ctx, diagnostic.LevelWarn, "flow_failed", source, target, s.ID, header.FlowID, err)
	}
}

func (s *portalSession) handleUDPControl(ctx context.Context, conn net.Conn, source net.Addr, header wire.FlowHeader, target string, pending *pendingUDPControl) error {
	if err := validateFlowTransport(header, wire.CarrierUDP); err != nil {
		s.Handler.rejectFlowSetupGeneration(conn, s.ID, s.Generation, true, header, wire.FlowErrorCodeMetadataConflict)
		_ = conn.Close()
		return err
	}

	half := udpHalf{Role: header.Role}
	switch header.Role {
	case wire.FlowRoleOpen:
		flow := newNowuFlow(s, header.FlowID, target)
		if err := s.activateNOWUFlow(flow, pending); err != nil {
			flow.shutdown(err)
			rejectQUICControl(conn, header, setupFailureCode(err))
			_ = conn.Close()
			return err
		}
		half.Uplink = flow
		err := s.Handler.submitAndRouteUDPGeneration(ctx, source, s.ID, s.Generation, true, header, target, half)
		_ = conn.Close()
		return err
	case wire.FlowRoleAttach:
		half.Downlink = newQUICUDPDownlink(conn, s.SendDatagram, s.maxDatagramSize, s.closeTransport)
		return s.Handler.submitAndRouteUDPGeneration(ctx, source, s.ID, s.Generation, true, header, target, half)
	case wire.FlowRoleDuplex:
		flow := newNowuFlow(s, header.FlowID, target)
		if err := s.activateNOWUFlow(flow, pending); err != nil {
			flow.shutdown(err)
			rejectQUICControl(conn, header, setupFailureCode(err))
			_ = conn.Close()
			return err
		}
		half.Uplink = flow
		half.Downlink = newQUICUDPDownlink(conn, s.SendDatagram, s.maxDatagramSize, s.closeTransport)
		return s.Handler.submitAndRouteUDPGeneration(ctx, source, s.ID, s.Generation, true, header, target, half)
	default:
		_ = conn.Close()
		return fmt.Errorf("%w: invalid UDP flow role", ErrUnsupportedFlow)
	}
}

var errStalePendingUDPControl = errors.New("nowhere: stale pending UDP control")

func (s *portalSession) activateNOWUFlow(flow *nowuFlow, pending *pendingUDPControl) error {
	flow.mu.Lock()
	frames, err := s.activateNOWUFlowLocked(flow, pending)
	if err != nil {
		flow.mu.Unlock()
		return err
	}
	queued := false
	for _, frame := range frames {
		outcome := flow.pushFragmentLocked(frame.Fragment)
		if !outcome.Complete {
			continue
		}
		release := outcome.Release
		if release == nil {
			release = func() {}
		}
		select {
		case flow.waiter <- nowuQueuedPacket{payload: outcome.Packet, release: release}:
			queued = true
		default:
			release()
		}
	}
	flow.mu.Unlock()
	if queued {
		flow.resetIdle()
	}
	return nil
}

func (s *portalSession) activateNOWUFlowLocked(flow *nowuFlow, pending *pendingUDPControl) ([]wire.UDPFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if pending == nil || s.pendingControls[flow.flowID] != pending {
		return nil, errStalePendingUDPControl
	}
	if s.flows[flow.flowID] != nil {
		return nil, ErrDuplicateHalf
	}
	flow.ownsReassembly.Store(true)
	s.flows[flow.flowID] = flow
	frames := pending.frames
	s.removePendingControlLocked(flow.flowID, pending)
	return frames, nil
}

func (s *portalSession) insertNOWUFlow(flow *nowuFlow) error {
	flow.ownsReassembly.Store(true)
	switch s.insertFlow(flow.flowID, flow) {
	case flowInserted:
		return nil
	case flowDuplicate:
		flow.ownsReassembly.Store(false)
		return ErrDuplicateHalf
	default:
		flow.ownsReassembly.Store(false)
		return ErrClosed
	}
}

func rejectQUICControl(conn net.Conn, header wire.FlowHeader, code wire.FlowErrorCode) {
	_ = newSetupResult(conn, header.Kind, wire.CarrierUDP).reject(code)
}

func (s *portalSession) datagramLoop(ctx context.Context, pending [][]byte) {
	for _, data := range pending {
		s.handleDatagram(ctx, data)
	}
	for {
		data, err := s.Conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		s.handleDatagram(ctx, data)
	}
}

func (s *portalSession) handleDatagram(ctx context.Context, data []byte) {
	if len(data) >= 4 && string(data[:4]) == wire.UDPFrameMagic {
		s.handleNowu(ctx, data)
	}
}

func (s *portalSession) handleNowu(ctx context.Context, data []byte) {
	frame, err := wire.DecodeUDPFrame(data)
	if err != nil {
		return
	}
	switch frame.Type {
	case wire.UDPFrameData:
		if flow := s.getFlow(frame.FlowID); flow != nil {
			flow.deliverFragment(frame.Fragment)
		} else {
			// Only a validated control already waiting for FIN may preactivate DATA.
			_ = s.bufferPendingUDPData(frame, len(data))
		}
	case wire.UDPFrameClose:
		if flow := s.getFlow(frame.FlowID); flow != nil {
			flow.shutdown(io.EOF)
		}
	}
}

// --- NOWU UDP flow as net.PacketConn ---

type nowuFlow struct {
	session        *portalSession
	flowID         uint64
	target         string
	dest           net.Addr
	waiter         chan nowuQueuedPacket
	done           chan struct{}
	mu             sync.Mutex
	closed         bool
	closeErr       error
	closeOnce      sync.Once
	readDL         deadlineSignal
	writeDL        deadlineSignal
	idle           *time.Timer
	ownsReassembly atomic.Bool
	nextPacketID   atomic.Uint32
}

type nowuQueuedPacket struct {
	payload []byte
	release func()
}

func newNowuFlow(session *portalSession, flowID uint64, target string) *nowuFlow {
	flow := &nowuFlow{
		session: session,
		flowID:  flowID,
		target:  target,
		dest:    parseTargetAddr(target),
		waiter:  make(chan nowuQueuedPacket, session.Handler.config.limits.UDPQueuePackets),
		done:    make(chan struct{}),
	}
	flow.resetIdle()
	return flow
}

const (
	nowuPartialLimit = 64
	nowuPartialTTL   = 10 * time.Second
)

func (f *nowuFlow) deliverFragment(fragment wire.UDPFragment) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	outcome := f.pushFragmentLocked(fragment)
	f.mu.Unlock()
	if outcome.Complete {
		f.enqueue(outcome.Packet, outcome.Release)
	}
}

func (f *nowuFlow) pushFragmentLocked(fragment wire.UDPFragment) reassemblyOutcome {
	now := time.Now()
	if f.session.Handler != nil && f.session.Handler.now != nil {
		now = f.session.Handler.now()
	}
	return f.session.reassembler.Push(f.flowID, fragment, now)
}

func (f *nowuFlow) deliver(payload []byte) {
	if !f.session.reserveQueueBytes(len(payload)) {
		return
	}
	copyPayload := append([]byte(nil), payload...)
	f.enqueue(copyPayload, func() { f.session.releaseQueueBytes(len(copyPayload)) })
}

func (f *nowuFlow) enqueue(payload []byte, release func()) {
	if release == nil {
		release = func() {}
	}
	packet := nowuQueuedPacket{payload: payload, release: release}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		release()
		return
	}
	select {
	case f.waiter <- packet:
		f.mu.Unlock()
		f.resetIdle()
	default:
		f.mu.Unlock()
		release()
	}
}

func (f *nowuFlow) shutdown(err error) {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.closeErr = err
		if f.idle != nil {
			f.idle.Stop()
		}
		f.mu.Unlock()
		if f.ownsReassembly.Load() && f.session.reassembler != nil {
			f.session.reassembler.RemoveFlow(f.flowID)
		}
		close(f.done)
		for {
			select {
			case packet := <-f.waiter:
				packet.release()
			default:
				f.session.removeFlow(f.flowID, f)
				return
			}
		}
	})
}

func (f *nowuFlow) ReadPacket() ([]byte, error) {
	select {
	case packet := <-f.waiter:
		packet.release()
		f.resetIdle()
		return packet.payload, nil
	case <-f.done:
		return nil, f.err()
	case <-f.readDL.wait():
		return nil, deadlineError()
	}
}

func (f *nowuFlow) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	payload, err := f.ReadPacket()
	if err != nil {
		return 0, nil, err
	}
	return copy(p, payload), f.dest, nil
}

func (f *nowuFlow) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	select {
	case <-f.done:
		return 0, f.err()
	case <-f.writeDL.wait():
		return 0, deadlineError()
	default:
	}
	packetID := f.nextPacketID.Add(1)
	if packetID == 0 {
		packetID = f.nextPacketID.Add(1)
	}
	frames, err := wire.EncodeUDPDataFragments(f.flowID, packetID, p, 1200)
	if err != nil {
		return 0, err
	}
	for _, frame := range frames {
		if err := f.session.SendDatagram(frame); err != nil {
			return 0, err
		}
	}
	f.resetIdle()
	return len(p), nil
}

func (f *nowuFlow) Close() error {
	f.shutdown(net.ErrClosed)
	return nil
}

func (f *nowuFlow) LocalAddr() net.Addr {
	if s := f.session; s != nil && s.Conn != nil {
		return s.Conn.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (f *nowuFlow) SetDeadline(value time.Time) error {
	f.readDL.set(value)
	f.writeDL.set(value)
	return nil
}
func (f *nowuFlow) SetReadDeadline(value time.Time) error {
	f.readDL.set(value)
	return nil
}
func (f *nowuFlow) SetWriteDeadline(value time.Time) error {
	f.writeDL.set(value)
	return nil
}

func (f *nowuFlow) resetIdle() {
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

func (f *nowuFlow) err() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closeErr != nil {
		return f.closeErr
	}
	return io.EOF
}

var _ net.PacketConn = (*nowuFlow)(nil)

// --- stream helpers ---

type bufferedStreamConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedStreamConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type quicStreamConn struct {
	QuicStream
	local  net.Addr
	remote net.Addr
	once   sync.Once
}

func wrapQuicStream(stream QuicStream, local, remote net.Addr) net.Conn {
	return &quicStreamConn{QuicStream: stream, local: local, remote: remote}
}

func (c *quicStreamConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return &net.UDPAddr{}
}

func (c *quicStreamConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return &net.UDPAddr{}
}

func (c *quicStreamConn) Close() error {
	var err error
	c.once.Do(func() {
		c.CancelRead(uint64(wire.CloseErrCodeOK))
		err = c.QuicStream.Close()
	})
	return err
}

func (c *quicStreamConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

var (
	_ net.Conn = (*quicStreamConn)(nil)
	_ net.Conn = (*bufferedStreamConn)(nil)
)
