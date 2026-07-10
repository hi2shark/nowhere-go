package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/go-nowhere/diagnostic"
	"github.com/hi2shark/go-nowhere/wire"
)

const (
	preAuthDatagramBudget = 64 * 1024
)

// sessionManager tracks authenticated QUIC sessions by Nowhere session_id.
// A newer connection with the same session_id replaces the previous one.
type sessionManager struct {
	mu       sync.Mutex
	sessions map[wire.SessionID]*portalSession
	max      int
	closed   bool
}

func newSessionManager() *sessionManager {
	return &sessionManager{sessions: make(map[wire.SessionID]*portalSession), max: DefaultActiveQUICSessions}
}

func (m *sessionManager) configureLimit(max int) {
	m.mu.Lock()
	m.max = max
	m.mu.Unlock()
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
	if old == nil && len(m.sessions) >= m.max {
		m.mu.Unlock()
		return ErrSessionLimit
	}
	m.sessions[session.ID] = session
	m.mu.Unlock()
	if old != nil && old != session {
		old.Close()
	}
	return nil
}

func (m *sessionManager) Unregister(session *portalSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.sessions[session.ID]; ok && cur == session {
		delete(m.sessions, session.ID)
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
		session.Close()
	}
}

// portalSession is one authenticated QUIC connection (via QuicConn).
type portalSession struct {
	ID      wire.SessionID
	Conn    QuicConn
	Handler *Handler
	Source  net.Addr

	cancel context.CancelFunc

	mu          sync.Mutex
	flows       map[uint64]*compactUDPFlow
	asymUplinks map[uint64]*quicUDPUplink
	queuedBytes int
	closed      bool
}

func newPortalSession(id wire.SessionID, conn QuicConn, handler *Handler, source net.Addr) *portalSession {
	return &portalSession{
		ID:          id,
		Conn:        conn,
		Handler:     handler,
		Source:      source,
		flows:       make(map[uint64]*compactUDPFlow),
		asymUplinks: make(map[uint64]*quicUDPUplink),
	}
}

func (s *portalSession) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	flows := s.flows
	s.flows = nil
	uplinks := s.asymUplinks
	s.asymUplinks = nil
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, f := range flows {
		f.shutdown(net.ErrClosed)
	}
	for _, uplink := range uplinks {
		_ = uplink.Close()
	}
	if s.Conn != nil {
		_ = s.Conn.CloseWithError(uint64(wire.CloseErrCodeOK), "")
	}
}

func (s *portalSession) SendDatagram(b []byte) error {
	return s.Conn.SendDatagram(b)
}

func (s *portalSession) getFlow(id uint64) *compactUDPFlow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flows[id]
}

func (s *portalSession) putFlow(id uint64, flow *compactUDPFlow) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if _, exists := s.flows[id]; exists {
		return false
	}
	if len(s.flows)+len(s.asymUplinks) >= s.Handler.config.limits.QUICFlowsPerSession {
		return false
	}
	s.flows[id] = flow
	return true
}

func (s *portalSession) removeFlow(id uint64) {
	s.mu.Lock()
	delete(s.flows, id)
	s.mu.Unlock()
}

func (s *portalSession) getAsymUplink(id uint64) *quicUDPUplink {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asymUplinks[id]
}

func (s *portalSession) putAsymUplink(id uint64, up *quicUDPUplink) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.flows)+len(s.asymUplinks) >= s.Handler.config.limits.QUICFlowsPerSession {
		return false
	}
	if s.asymUplinks == nil {
		s.asymUplinks = make(map[uint64]*quicUDPUplink)
	}
	if _, exists := s.asymUplinks[id]; exists {
		return false
	}
	s.asymUplinks[id] = up
	return true
}

func (s *portalSession) removeAsymUplink(id uint64) {
	s.mu.Lock()
	delete(s.asymUplinks, id)
	s.mu.Unlock()
}

func (s *portalSession) reserveQueueBytes(count int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || count < 0 || s.queuedBytes+count > s.Handler.config.limits.QUICQueueBytes {
		return false
	}
	s.queuedBytes += count
	return true
}

func (s *portalSession) releaseQueueBytes(count int) {
	s.mu.Lock()
	s.queuedBytes -= count
	if s.queuedBytes < 0 {
		s.queuedBytes = 0
	}
	s.mu.Unlock()
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
	source := conn.RemoteAddr()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	session, pending, err := h.authenticateQuic(ctx, conn)
	if err != nil {
		_ = conn.CloseWithError(1, "access denied")
		h.emit(ctx, diagnostic.LevelError, "auth_failed", source, "", wire.SessionID{}, 0, err)
		return err
	}
	session.cancel = cancel
	if err := h.sessions.Register(session); err != nil {
		_ = conn.CloseWithError(1, "access denied")
		return err
	}
	defer h.sessions.Unregister(session)
	defer session.Close()

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

	br := newPeekReader(conn)
	peek, err := br.Peek(1)
	if err != nil {
		_ = conn.Close()
		return
	}

	var header *wire.FlowHeader
	if peek[0] == wire.FlowFrameMagic {
		fh, err := wire.ReadFlowHeader(br)
		if err != nil {
			_ = conn.Close()
			s.Handler.emit(ctx, diagnostic.LevelError, "request_read_failed", source, "", s.ID, 0, err)
			return
		}
		header = &fh
	}

	target, err := wire.DecodeTCPRequest(br, s.Handler.config.spec)
	if err != nil {
		_ = conn.Close()
		s.Handler.emit(ctx, diagnostic.LevelError, "request_read_failed", source, "", s.ID, 0, err)
		return
	}
	_ = conn.SetDeadline(time.Time{})
	streamConn := &bufferedStreamConn{Conn: conn, reader: br}

	if header != nil {
		s.handleAsymmetricStream(ctx, streamConn, source, *header, target)
		return
	}
	_ = s.Handler.handleStreamRequest(ctx, streamConn, source, s.ID, nil, target)
}

func (s *portalSession) handleAsymmetricStream(ctx context.Context, conn net.Conn, source net.Addr, header wire.FlowHeader, target string) {
	switch header.Kind {
	case wire.FlowKindTCP:
		_ = s.Handler.handleAsymmetricTCP(ctx, conn, source, s.ID, header, target)
	case wire.FlowKindUDP:
		if header.Role != wire.FlowRoleAttach {
			_ = conn.Close()
			return
		}
		if header.Downlink != wire.CarrierUDP {
			_ = conn.Close()
			return
		}
		half := udpHalf{
			Role:     wire.FlowRoleAttach,
			Downlink: newQUICUDPDownlink(s.SendDatagram),
		}
		_ = s.Handler.submitAndRouteUDP(ctx, source, s.ID, header, target, half)
		_ = conn.Close()
	default:
		_ = conn.Close()
	}
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
	if len(data) >= 2 && data[1] >= wire.UDPTypeOpenData && data[1] <= wire.UDPTypeCompactClose {
		s.handleCompact(ctx, data)
	}
}

func (s *portalSession) handleCompact(ctx context.Context, data []byte) {
	frame, err := wire.DecodeUDPCompact(data)
	if err != nil {
		return
	}
	switch frame.Type {
	case wire.UDPTypeOpenData:
		s.handleOpenData(ctx, frame)
	case wire.UDPTypeData:
		if flow := s.getFlow(frame.FlowID); flow != nil {
			flow.deliver(frame.Payload)
		} else if up := s.getAsymUplink(frame.FlowID); up != nil {
			up.Deliver(frame.Payload)
		} else {
			s.rejectFlow(frame.FlowID)
		}
	case wire.UDPTypeCompactClose:
		if flow := s.getFlow(frame.FlowID); flow != nil {
			flow.shutdown(io.EOF)
		}
	}
}

func (s *portalSession) handleOpenData(ctx context.Context, frame wire.CompactUDPFrame) {
	if existing := s.getFlow(frame.FlowID); existing != nil {
		if existing.target == frame.Target && existing.downlink == frame.Downlink {
			existing.deliver(frame.Payload)
			if existing.isAcked() {
				existing.sendAck()
			}
			return
		}
		s.rejectFlow(frame.FlowID)
		return
	}
	if up := s.getAsymUplink(frame.FlowID); up != nil {
		up.Deliver(frame.Payload)
		return
	}

	if frame.Downlink == wire.CarrierUDP {
		flow := newCompactUDPFlow(s, frame.FlowID, frame.Target, frame.Downlink)
		if !s.putFlow(frame.FlowID, flow) {
			s.rejectFlow(frame.FlowID)
			return
		}
		flow.deliver(frame.Payload)
		flow.routedOnce.Do(func() {
			flow.sendAck()
			flowCtx := ContextWithCloseHandler(ctx, flow.shutdown)
			go func() { _ = s.Handler.routePacket(flowCtx, flow, s.Source, frame.Target) }()
		})
		return
	}

	uplink := newQUICUDPUplink(s)
	uplink.onClose = func() { s.removeAsymUplink(frame.FlowID) }
	uplink.Deliver(frame.Payload)
	if !s.putAsymUplink(frame.FlowID, uplink) {
		_ = uplink.Close()
		s.rejectFlow(frame.FlowID)
		return
	}
	ack := newQUICCompactAck(s.SendDatagram, nil)
	header := wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		FlowID:   frame.FlowID,
		Kind:     wire.FlowKindUDP,
		Uplink:   wire.CarrierUDP,
		Downlink: frame.Downlink,
	}
	half := udpHalf{
		Role:       wire.FlowRoleOpen,
		Uplink:     uplink,
		compactAck: ack,
	}
	go func() {
		_ = s.Handler.submitAndRouteUDP(ctx, s.Source, s.ID, header, frame.Target, half)
	}()
}

func (s *portalSession) rejectFlow(flowID uint64) {
	if flow := s.getFlow(flowID); flow != nil {
		flow.shutdown(errors.New("nowhere: compact flow rejected"))
	}
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeCompactClose, flowID, nil)
	if err == nil {
		_ = s.SendDatagram(frame)
	}
}

// --- compact UDP flow as net.PacketConn ---

type compactUDPFlow struct {
	session    *portalSession
	flowID     uint64
	target     string
	downlink   wire.Carrier
	dest       net.Addr
	waiter     chan []byte
	done       chan struct{}
	acked      bool
	mu         sync.Mutex
	closed     bool
	closeErr   error
	closeOnce  sync.Once
	routedOnce sync.Once
	readDL     deadlineSignal
	writeDL    deadlineSignal
	idle       *time.Timer
}

func newCompactUDPFlow(session *portalSession, flowID uint64, target string, downlink wire.Carrier) *compactUDPFlow {
	flow := &compactUDPFlow{
		session:  session,
		flowID:   flowID,
		target:   target,
		downlink: downlink,
		dest:     parseTargetAddr(target),
		waiter:   make(chan []byte, session.Handler.config.limits.QUICQueuePackets),
		done:     make(chan struct{}),
	}
	flow.resetIdle()
	return flow
}

func (f *compactUDPFlow) deliver(payload []byte) {
	if !f.session.reserveQueueBytes(len(payload)) {
		return
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		f.session.releaseQueueBytes(len(payload))
		return
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	select {
	case f.waiter <- cp:
		f.mu.Unlock()
		f.resetIdle()
	default:
		f.mu.Unlock()
		f.session.releaseQueueBytes(len(cp))
	}
}

func (f *compactUDPFlow) markAcked() {
	f.mu.Lock()
	f.acked = true
	f.mu.Unlock()
}

func (f *compactUDPFlow) isAcked() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.acked
}

func (f *compactUDPFlow) shutdown(err error) {
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
				f.session.removeFlow(f.flowID)
				return
			}
		}
	})
}

func (f *compactUDPFlow) sendAck() {
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeOpenAck, f.flowID, nil)
	if err != nil {
		return
	}
	if err := f.session.SendDatagram(frame); err == nil {
		f.markAcked()
	}
}

func (f *compactUDPFlow) sendClose() {
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeCompactClose, f.flowID, nil)
	if err == nil {
		_ = f.session.SendDatagram(frame)
	}
}

func (f *compactUDPFlow) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case payload := <-f.waiter:
		f.session.releaseQueueBytes(len(payload))
		f.resetIdle()
		n = copy(p, payload)
		return n, f.dest, nil
	case <-f.done:
		return 0, nil, f.err()
	case <-f.readDL.wait():
		return 0, nil, deadlineError()
	}
}

func (f *compactUDPFlow) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case <-f.done:
		return 0, f.err()
	case <-f.writeDL.wait():
		return 0, deadlineError()
	default:
	}
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeData, f.flowID, p)
	if err != nil {
		return 0, err
	}
	if err := f.session.SendDatagram(frame); err != nil {
		return 0, err
	}
	f.resetIdle()
	return len(p), nil
}

func (f *compactUDPFlow) Close() error {
	f.sendClose()
	f.shutdown(net.ErrClosed)
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

// --- stream helpers ---

type peekReader struct {
	r      io.Reader
	buf    []byte
	offset int
}

func newPeekReader(r io.Reader) *peekReader { return &peekReader{r: r} }

func (p *peekReader) Peek(n int) ([]byte, error) {
	if len(p.buf)-p.offset >= n {
		return p.buf[p.offset : p.offset+n], nil
	}
	need := n - (len(p.buf) - p.offset)
	tmp := make([]byte, need)
	if _, err := io.ReadFull(p.r, tmp); err != nil {
		return nil, err
	}
	p.buf = append(p.buf[p.offset:], tmp...)
	p.offset = 0
	return p.buf[:n], nil
}

func (p *peekReader) Read(b []byte) (int, error) {
	if p.offset < len(p.buf) {
		n := copy(b, p.buf[p.offset:])
		p.offset += n
		if p.offset == len(p.buf) {
			p.buf = nil
			p.offset = 0
		}
		return n, nil
	}
	return p.r.Read(b)
}

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
