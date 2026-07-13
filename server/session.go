package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/diagnostic"
	"github.com/hi2shark/nowhere-go/wire"
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
	udp         udpRegistryState
	queuedBytes int
	closed      bool
}

func newPortalSession(id wire.SessionID, conn QuicConn, handler *Handler, source net.Addr) *portalSession {
	return &portalSession{
		ID:      id,
		Conn:    conn,
		Handler: handler,
		Source:  source,
		udp:     newUDPRegistryState(),
	}
}

func (s *portalSession) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	compact := s.udp.compact
	legacy := s.udp.legacy
	s.udp.compact = nil
	s.udp.legacy = nil
	s.udp.activeFlows = 0
	cancel := s.cancel
	s.mu.Unlock()

	for _, entry := range compact {
		if entry.lease != nil {
			entry.lease.Abort(entry.generation)
		}
	}
	if s.Conn != nil {
		_ = s.Conn.CloseWithError(uint64(wire.CloseErrCodeOK), "")
	}
	if cancel != nil {
		cancel()
	}
	for _, entry := range compact {
		if entry.symmetric != nil {
			entry.symmetric.shutdown(net.ErrClosed)
		}
		if entry.pair != nil && s.Handler != nil && s.Handler.pairing != nil {
			s.Handler.pairing.finishUDP(entry.pair, net.ErrClosed)
		}
	}
	for _, flow := range legacy {
		flow.shutdown(net.ErrClosed)
	}
	if s.Handler != nil && s.Handler.pairing != nil {
		s.Handler.pairing.cancelUDPSession(s.ID, net.ErrClosed)
	}
}

func (s *portalSession) SendDatagram(b []byte) error {
	return s.Conn.SendDatagram(b)
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
	guard, ok := h.admission.tryAcquire(source)
	if !ok {
		_ = conn.CloseWithError(uint64(wire.CloseErrCodeOK), "")
		h.emitAdmissionLimited(parent, source)
		return report(ErrAdmissionLimit)
	}
	releaseAdmission := guard.Release
	defer releaseAdmission()

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

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
		if err := s.Handler.handleAsymmetricTCP(ctx, conn, source, s.ID, header, target); err != nil {
			if !IsReported(err) {
				s.Handler.emit(ctx, diagnostic.LevelWarn, "asymmetric_tcp_failed", source, target, s.ID, header.FlowID, err)
			}
		}
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
		if err := s.Handler.submitAndRouteUDP(ctx, source, s.ID, header, target, half); err != nil {
			if !IsReported(err) {
				s.Handler.emit(ctx, diagnostic.LevelWarn, "asymmetric_udp_failed", source, target, s.ID, header.FlowID, err)
			}
		}
		_ = conn.Close()
	default:
		_ = conn.Close()
	}
}

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
