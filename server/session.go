package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/go-nowhere/wire"
)

const (
	preAuthDatagramBudget = 64 * 1024
	defaultAuthTimeout    = 10 * time.Second
)

// SessionManager tracks authenticated QUIC sessions by Nowhere session_id.
// A newer connection with the same session_id replaces the previous one.
type SessionManager struct {
	mu       sync.Mutex
	sessions map[wire.SessionID]*PortalSession
}

func NewSessionManager() *SessionManager {
	return &SessionManager{sessions: make(map[wire.SessionID]*PortalSession)}
}

func (m *SessionManager) Register(session *PortalSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.sessions[session.ID]; ok && old != session {
		old.Close()
	}
	m.sessions[session.ID] = session
}

func (m *SessionManager) Unregister(session *PortalSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.sessions[session.ID]; ok && cur == session {
		delete(m.sessions, session.ID)
	}
}

func (m *SessionManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		s.Close()
		delete(m.sessions, id)
	}
}

// PortalSession is one authenticated QUIC connection (via QuicConn).
type PortalSession struct {
	ID      wire.SessionID
	Conn    QuicConn
	Handler *Handler
	Source  net.Addr

	cancel context.CancelFunc

	mu          sync.Mutex
	flows       map[uint64]*compactUDPFlow
	asymUplinks map[uint64]*QuicUDPUplink
	closed      bool
}

func NewPortalSession(id wire.SessionID, conn QuicConn, handler *Handler, source net.Addr) *PortalSession {
	return &PortalSession{
		ID:          id,
		Conn:        conn,
		Handler:     handler,
		Source:      source,
		flows:       make(map[uint64]*compactUDPFlow),
		asymUplinks: make(map[uint64]*QuicUDPUplink),
	}
}

func (s *PortalSession) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	flows := s.flows
	s.flows = nil
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, f := range flows {
		f.shutdown(net.ErrClosed)
	}
	_ = s.Conn.CloseWithError(uint64(wire.CloseErrCodeOK), "")
}

func (s *PortalSession) SendDatagram(b []byte) error {
	return s.Conn.SendDatagram(b)
}

func (s *PortalSession) getFlow(id uint64) *compactUDPFlow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flows[id]
}

func (s *PortalSession) putFlow(id uint64, flow *compactUDPFlow) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if _, exists := s.flows[id]; exists {
		return false
	}
	s.flows[id] = flow
	return true
}

func (s *PortalSession) removeFlow(id uint64) {
	s.mu.Lock()
	delete(s.flows, id)
	s.mu.Unlock()
}

func (s *PortalSession) getAsymUplink(id uint64) *QuicUDPUplink {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asymUplinks[id]
}

func (s *PortalSession) putAsymUplink(id uint64, up *QuicUDPUplink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.asymUplinks == nil {
		s.asymUplinks = make(map[uint64]*QuicUDPUplink)
	}
	s.asymUplinks[id] = up
}

func (s *PortalSession) removeAsymUplink(id uint64) {
	s.mu.Lock()
	delete(s.asymUplinks, id)
	s.mu.Unlock()
}

// ServeQuicConn authenticates and serves one QuicConn until it closes.
func (h *Handler) ServeQuicConn(parent context.Context, conn QuicConn) {
	log := resolveLogger(h.Logger)
	source := conn.RemoteAddr()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	session, pending, err := h.authenticateQuic(ctx, conn)
	if err != nil {
		log.Errorf("nowhere quic auth from %v: %v", source, err)
		_ = conn.CloseWithError(1, "access denied")
		return
	}
	session.cancel = cancel
	if h.Sessions != nil {
		h.Sessions.Register(session)
		defer h.Sessions.Unregister(session)
	}
	defer session.Close()

	log.Infof("nowhere quic session from %v", source)
	go session.datagramLoop(ctx, pending)
	session.acceptStreams(ctx)
}

func (h *Handler) authenticateQuic(ctx context.Context, conn QuicConn) (*PortalSession, [][]byte, error) {
	authCtx, cancel := context.WithTimeout(ctx, defaultAuthTimeout)
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
		id, err := wire.ReadAuthFrame(stream, h.Config.Key, h.Config.Spec)
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
						return nil, nil, res.err
					}
					return NewPortalSession(res.id, conn, h, conn.RemoteAddr()), pending, nil
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
			return nil, nil, authCtx.Err()
		}
	}
}

func (s *PortalSession) acceptStreams(ctx context.Context) {
	for {
		stream, err := s.Conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.handleStream(ctx, stream)
	}
}

func (s *PortalSession) handleStream(ctx context.Context, stream QuicStream) {
	conn := wrapQuicStream(stream, s.Conn.LocalAddr(), s.Conn.RemoteAddr())
	source := s.Source
	log := resolveLogger(s.Handler.Logger)

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
			log.Errorf("nowhere quic flow header from %v: %v", source, err)
			return
		}
		header = &fh
	}

	target, err := wire.DecodeTCPRequest(br, s.Handler.Config.Spec)
	if err != nil {
		_ = conn.Close()
		log.Errorf("nowhere quic tcp request from %v: %v", source, err)
		return
	}
	streamConn := &bufferedStreamConn{Conn: conn, reader: br}

	if header != nil {
		s.handleAsymmetricStream(ctx, streamConn, source, *header, target)
		return
	}
	s.Handler.HandleStreamRequest(ctx, streamConn, source, s.ID, nil, target, nil)
}

func (s *PortalSession) handleAsymmetricStream(ctx context.Context, conn net.Conn, source net.Addr, header wire.FlowHeader, target string) {
	log := resolveLogger(s.Handler.Logger)
	switch header.Kind {
	case wire.FlowKindTCP:
		s.Handler.handleAsymmetricTCP(ctx, conn, source, s.ID, header, target, nil)
	case wire.FlowKindUDP:
		if header.Role != wire.FlowRoleAttach {
			_ = conn.Close()
			log.Errorf("nowhere: UDP uplink must use DATAGRAM")
			return
		}
		if header.Downlink != wire.CarrierUDP {
			_ = conn.Close()
			log.Errorf("nowhere: quic UDP ATTACH requires udp downlink")
			return
		}
		half := UDPHalf{
			Role:     wire.FlowRoleAttach,
			Downlink: NewQUICUDPDownlink(s.SendDatagram),
		}
		s.Handler.SubmitAndRouteUDP(ctx, source, s.ID, header, target, half, nil)
		_ = conn.Close()
	default:
		_ = conn.Close()
	}
}

func (s *PortalSession) datagramLoop(ctx context.Context, pending [][]byte) {
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

func (s *PortalSession) handleDatagram(ctx context.Context, data []byte) {
	if len(data) >= 2 && data[1] >= wire.UDPTypeOpenData && data[1] <= wire.UDPTypeCompactClose {
		s.handleCompact(ctx, data)
	}
}

func (s *PortalSession) handleCompact(ctx context.Context, data []byte) {
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

func (s *PortalSession) handleOpenData(ctx context.Context, frame wire.CompactUDPFrame) {
	log := resolveLogger(s.Handler.Logger)
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
			log.Infof("inbound quic packet connection to %s", frame.Target)
			flow.sendAck()
			go s.Handler.routePacket(ctx, flow, s.Source, frame.Target, func(err error) {
				flow.shutdown(err)
			})
		})
		return
	}

	uplink := NewQUICUDPUplink()
	uplink.Deliver(frame.Payload)
	s.putAsymUplink(frame.FlowID, uplink)
	ack := NewQUICCompactAck(s.SendDatagram, nil)
	header := wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		FlowID:   frame.FlowID,
		Kind:     wire.FlowKindUDP,
		Uplink:   wire.CarrierUDP,
		Downlink: frame.Downlink,
	}
	half := UDPHalf{
		Role:       wire.FlowRoleOpen,
		Uplink:     uplink,
		CompactAck: ack,
	}
	go func() {
		s.Handler.SubmitAndRouteUDP(ctx, s.Source, s.ID, header, frame.Target, half, func(err error) {
			s.removeAsymUplink(frame.FlowID)
			_ = uplink.Close()
		})
	}()
}

func (s *PortalSession) rejectFlow(flowID uint64) {
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
	session    *PortalSession
	flowID     uint64
	target     string
	downlink   wire.Carrier
	dest       net.Addr
	waiter     chan []byte
	acked      bool
	mu         sync.Mutex
	closed     bool
	closeErr   error
	closeOnce  sync.Once
	routedOnce sync.Once
}

func newCompactUDPFlow(session *PortalSession, flowID uint64, target string, downlink wire.Carrier) *compactUDPFlow {
	return &compactUDPFlow{
		session:  session,
		flowID:   flowID,
		target:   target,
		downlink: downlink,
		dest:     parseTargetAddr(target),
		waiter:   make(chan []byte, 64),
	}
}

func (f *compactUDPFlow) deliver(payload []byte) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	ch := f.waiter
	f.mu.Unlock()
	if ch == nil {
		return
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	select {
	case ch <- cp:
	default:
		select {
		case <-ch:
		default:
		}
		select {
		case ch <- cp:
		default:
		}
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
		ch := f.waiter
		f.waiter = nil
		f.mu.Unlock()
		if ch != nil {
			close(ch)
		}
		f.session.removeFlow(f.flowID)
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
	f.mu.Lock()
	ch := f.waiter
	closed := f.closed
	f.mu.Unlock()
	if closed && ch == nil {
		return 0, nil, f.err()
	}
	payload, ok := <-ch
	if !ok {
		return 0, nil, f.err()
	}
	n = copy(p, payload)
	return n, f.dest, nil
}

func (f *compactUDPFlow) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeData, f.flowID, p)
	if err != nil {
		return 0, err
	}
	if err := f.session.SendDatagram(frame); err != nil {
		return 0, err
	}
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

func (f *compactUDPFlow) SetDeadline(time.Time) error      { return nil }
func (f *compactUDPFlow) SetReadDeadline(time.Time) error  { return nil }
func (f *compactUDPFlow) SetWriteDeadline(time.Time) error { return nil }

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
