package bundle

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/wire"
)

const (
	quicDatagramFlowQueue = 64
	quicSendQueue         = 1
	quicReassemblySweep   = time.Second
)

// Invalidation has one owner: either a per-raw failure/explicit invalidation or
// backend Close. The owner removes the mux only after the host close completes.
const (
	quicInvalidationNone int32 = iota
	quicInvalidationRaw
	quicInvalidationBackendClose
	quicInvalidationFinished
)

var errManagedDatagramReceive = errors.New("nowhere: quic datagram receive is bundle managed")
var errQUICAuthenticationAborted = errors.New("nowhere: first quic stream closed before authentication")

const (
	quicSendQueued uint32 = iota
	quicSendStarted
	quicSendCompleted
	quicSendCanceled
)

type quicSendRequest struct {
	owner  *qSessionHandle
	frame  []byte
	result chan error
	state  atomic.Uint32
}

func (r *quicSendRequest) start() bool {
	return r.state.CompareAndSwap(quicSendQueued, quicSendStarted)
}

func (r *quicSendRequest) cancel() bool {
	return r.state.CompareAndSwap(quicSendQueued, quicSendCanceled)
}

func (r *quicSendRequest) finish(err error) {
	r.state.Store(quicSendCompleted)
	r.result <- err
}

// quicAuthFrameBuilder binds a fresh physical QUIC session to the bundle
// identity. It is supplied by the bundle (which owns the Credentials +
// Transport + Session ID) and called exactly once per physical session. The
// mux retains the result until the first flow commits.
type quicAuthFrameBuilder func(ctx context.Context, session carrier.QuicSession) (wire.AuthFrame, error)

// quicMuxBackend owns one receive loop and one bounded send owner for every
// physical QUIC session returned by the injected backend.
type quicMuxBackend struct {
	backend carrier.QuicBackend
	auth    quicAuthFrameBuilder

	mu       sync.Mutex
	sessions map[carrier.QuicSession]*quicSessionMux
	closed   bool
}

func newQUICMuxBackend(backend carrier.QuicBackend, auth quicAuthFrameBuilder) *quicMuxBackend {
	return &quicMuxBackend{
		backend:  backend,
		auth:     auth,
		sessions: make(map[carrier.QuicSession]*quicSessionMux),
	}
}

func (b *quicMuxBackend) AcquireSession(ctx context.Context) (carrier.QuicSession, error) {
	for {
		raw, err := b.backend.AcquireSession(ctx)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			return nil, errors.New("nowhere: nil quic session")
		}

		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return nil, net.ErrClosed
		}
		if session := b.sessions[raw]; session != nil {
			if session.invalidation.Load() != quicInvalidationNone {
				done := session.invalidationDone
				b.mu.Unlock()
				select {
				case <-done:
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			b.mu.Unlock()
			return session, nil
		}
		// First time the mux sees this physical session: derive and retain its
		// connection-bound auth frame. PrepareStream will reserve the first
		// stream and Commit will write auth || first FLOW in one operation.
		if b.auth == nil {
			b.mu.Unlock()
			b.backend.InvalidateSession(raw)
			return nil, errors.New("nowhere: missing quic authenticator")
		}
		authFrame, authErr := b.auth(ctx, raw)
		if authErr != nil {
			b.mu.Unlock()
			b.backend.InvalidateSession(raw)
			return nil, authErr
		}
		session := newQUICSessionMux(b, raw, authFrame)
		b.sessions[raw] = session
		b.mu.Unlock()
		return session, nil
	}
}

func (b *quicMuxBackend) InvalidateSession(session carrier.QuicSession) {
	raw := session
	var managed *quicSessionMux
	if state, ok := session.(*quicSessionMux); ok {
		managed = state
		raw = managed.raw
	} else {
		b.mu.Lock()
		managed = b.sessions[session]
		b.mu.Unlock()
	}
	if managed == nil {
		b.backend.InvalidateSession(raw)
		return
	}
	managed.invalidateRaw(net.ErrClosed)
	<-managed.loopDone
	<-managed.sendLoopDone
}

func (b *quicMuxBackend) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	sessions := make([]*quicSessionMux, 0, len(b.sessions))
	for _, session := range b.sessions {
		sessions = append(sessions, session)
	}
	b.mu.Unlock()

	for _, session := range sessions {
		session.prepareBackendClose()
	}
	err := b.backend.Close()
	for _, session := range sessions {
		session.completeBackendClose()
	}
	for _, session := range sessions {
		<-session.loopDone
		<-session.sendLoopDone
	}
	return err
}

func (b *quicMuxBackend) remove(session *quicSessionMux) {
	b.mu.Lock()
	if b.sessions[session.raw] == session {
		delete(b.sessions, session.raw)
	}
	b.mu.Unlock()
}

var _ carrier.QuicBackend = (*quicMuxBackend)(nil)

// quicSessionMux presents one carrier session, runs the single receive loop,
// and owns every raw SendDatagram call. DATA retains bounded native
// backpressure; CLOSE uses a reliable in-memory queue so flow teardown cannot
// be lost while the DATA queue or raw sender is blocked. Fragment reassembly
// delegates to the wire.DatagramReassembler (matches the Rust oracle).
type quicSessionMux struct {
	backend *quicMuxBackend
	raw     carrier.QuicSession
	ctx     context.Context
	cancel  context.CancelFunc

	authMu       sync.Mutex
	authFrame    wire.AuthFrame
	authClaimed  bool
	authComplete bool
	authErr      error
	authDone     chan struct{}

	mu          sync.Mutex
	flows       map[wire.FlowID]*quicDatagramFlow
	reassembler *wire.DatagramReassembler
	closeQueue  [][]byte
	started     bool
	closed      bool
	cause       error

	startOnce        sync.Once
	closeOnce        sync.Once
	finishOnce       sync.Once
	invalidation     atomic.Int32
	invalidationDone chan struct{}
	done             chan struct{}
	loopDone         chan struct{}
	sendQueue        chan *quicSendRequest
	closeReady       chan struct{}
	sendLoopDone     chan struct{}
}

func newQUICSessionMux(backend *quicMuxBackend, raw carrier.QuicSession, authFrame wire.AuthFrame) *quicSessionMux {
	ctx, cancel := context.WithCancel(context.Background())
	session := &quicSessionMux{
		backend:          backend,
		raw:              raw,
		ctx:              ctx,
		cancel:           cancel,
		authFrame:        authFrame,
		authDone:         make(chan struct{}),
		flows:            make(map[wire.FlowID]*quicDatagramFlow),
		reassembler:      wire.NewDatagramReassembler(wire.DefaultReassemblyConfig()),
		invalidationDone: make(chan struct{}),
		done:             make(chan struct{}),
		loopDone:         make(chan struct{}),
		sendQueue:        make(chan *quicSendRequest, quicSendQueue),
		closeReady:       make(chan struct{}, 1),
		sendLoopDone:     make(chan struct{}),
	}
	go session.sendLoop()
	return session
}

func (s *quicSessionMux) PrepareStream(ctx context.Context) (carrier.QuicPreparedStream, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	s.authMu.Lock()
	if s.authComplete {
		err := s.authErr
		s.authMu.Unlock()
		if err != nil {
			return nil, err
		}
		return s.raw.PrepareStream(ctx)
	}
	if s.authClaimed {
		done := s.authDone
		s.authMu.Unlock()
		select {
		case <-done:
			s.authMu.Lock()
			err := s.authErr
			s.authMu.Unlock()
			if err != nil {
				return nil, err
			}
			return s.raw.PrepareStream(ctx)
		case <-s.done:
			return nil, s.terminalError()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.authClaimed = true
	s.authMu.Unlock()

	stream, err := s.raw.PrepareStream(ctx)
	if err != nil {
		s.failAuthentication(err)
		return nil, err
	}
	return &quicAuthPreparedStream{session: s, stream: stream}, nil
}

func (s *quicSessionMux) completeAuthentication(err error) {
	s.authMu.Lock()
	if !s.authComplete {
		s.authComplete = true
		s.authErr = err
		close(s.authDone)
	}
	s.authMu.Unlock()
}

func (s *quicSessionMux) failAuthentication(err error) {
	if err == nil {
		err = errQUICAuthenticationAborted
	}
	s.completeAuthentication(err)
	s.invalidateRaw(err)
}

// quicAuthPreparedStream owns the first raw stream. Its single Commit sends
// the fixed auth frame and the first FLOW setup as one opaque payload, keeping
// the caller's FIN choice for the logical flow.
type quicAuthPreparedStream struct {
	session *quicSessionMux
	stream  carrier.QuicPreparedStream
	once    sync.Once
}

func (p *quicAuthPreparedStream) Commit(ctx context.Context, setup []byte, finishWrite bool) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	p.once.Do(func() {
		if p.session == nil || p.stream == nil {
			err = net.ErrClosed
			return
		}
		payload := make([]byte, 0, wire.AuthFrameLen+len(setup))
		payload = append(payload, p.session.authFrame[:]...)
		payload = append(payload, setup...)
		conn, err = p.stream.Commit(ctx, payload, finishWrite)
		if err == nil && conn == nil {
			err = net.ErrClosed
		}
		if err != nil {
			p.session.failAuthentication(err)
			return
		}
		p.session.completeAuthentication(nil)
	})
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (p *quicAuthPreparedStream) Close() error {
	var err error
	p.once.Do(func() {
		if p.stream != nil {
			err = p.stream.Close()
		}
		if p.session != nil {
			p.session.failAuthentication(errors.Join(errQUICAuthenticationAborted, err))
		}
	})
	return err
}

// TLSExporter delegates to the underlying physical session. The bundle reads
// it once during authentication (before the mux caches the session), so this
// method exists primarily to satisfy the carrier.QuicSession interface for the
// cached wrapper.
func (s *quicSessionMux) TLSExporter() (wire.TLSExporter, error) {
	return s.raw.TLSExporter()
}

func (s *quicSessionMux) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, errManagedDatagramReceive
}

func (s *quicSessionMux) CurrentMaxDatagramSize() int { return s.raw.CurrentMaxDatagramSize() }
func (s *quicSessionMux) SendDatagram(frame []byte) error {
	return s.sendDatagram(nil, frame, nil)
}
func (s *quicSessionMux) LocalAddr() net.Addr { return s.raw.LocalAddr() }

func (s *quicSessionMux) sendDatagram(owner *qSessionHandle, frame []byte, deadline *datagramDeadline) error {
	request := &quicSendRequest{owner: owner, frame: frame, result: make(chan error, 1)}
	var ownerDone <-chan struct{}
	if owner != nil {
		ownerDone = owner.doneSignal()
	}
	for {
		at, deadlineSignal, deadlineClosed := deadline.snapshot()
		if deadlineClosed {
			return net.ErrClosed
		}
		if deadlineExpired(at) {
			return errDatagramDeadline
		}
		select {
		case s.sendQueue <- request:
			goto queued
		case <-deadlineSignal:
			continue
		case <-ownerDone:
			return net.ErrClosed
		case <-s.done:
			return s.terminalError()
		}
	}

queued:
	for {
		select {
		case <-s.done:
			request.cancel()
			return s.terminalError()
		default:
		}
		if request.state.Load() == quicSendCompleted {
			return <-request.result
		}
		at, deadlineSignal, deadlineClosed := deadline.snapshot()
		if deadlineClosed {
			if request.cancel() {
				return net.ErrClosed
			}
			if request.state.Load() == quicSendCompleted {
				return <-request.result
			}
			return net.ErrClosed
		}
		if deadlineExpired(at) {
			if request.cancel() {
				return errDatagramDeadline
			}
			switch request.state.Load() {
			case quicSendCompleted:
				return <-request.result
			case quicSendStarted:
				s.invalidateRaw(net.ErrClosed)
			}
			return errDatagramDeadline
		}
		select {
		case err := <-request.result:
			select {
			case <-s.done:
				return s.terminalError()
			default:
				return err
			}
		case <-deadlineSignal:
			continue
		case <-ownerDone:
			if request.cancel() {
				return net.ErrClosed
			}
			if request.state.Load() == quicSendCompleted {
				return <-request.result
			}
			return net.ErrClosed
		case <-s.done:
			request.cancel()
			return s.terminalError()
		}
	}
}

func (s *quicSessionMux) enqueueClose(frame []byte) error {
	s.mu.Lock()
	if s.closed {
		cause := s.cause
		s.mu.Unlock()
		if cause == nil {
			return net.ErrClosed
		}
		return cause
	}
	s.closeQueue = append(s.closeQueue, bytes.Clone(frame))
	select {
	case s.closeReady <- struct{}{}:
	default:
	}
	s.mu.Unlock()
	return nil
}

func (s *quicSessionMux) popClose() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.closeQueue) == 0 {
		return nil
	}
	frame := s.closeQueue[0]
	s.closeQueue[0] = nil
	s.closeQueue = s.closeQueue[1:]
	if len(s.closeQueue) > 0 {
		select {
		case s.closeReady <- struct{}{}:
		default:
		}
	}
	return frame
}

func (s *quicSessionMux) sendLoop() {
	defer close(s.sendLoopDone)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		if frame := s.popClose(); frame != nil {
			if err := s.raw.SendDatagram(frame); err != nil {
				select {
				case <-s.done:
					return
				default:
				}
				s.invalidateRaw(err)
				return
			}
			continue
		}
		select {
		case request := <-s.sendQueue:
			if !request.start() {
				continue
			}
			if request.owner != nil {
				if err := request.owner.stateError(); err != nil {
					request.finish(err)
					continue
				}
			}
			request.finish(s.raw.SendDatagram(request.frame))
		case <-s.closeReady:
		case <-s.done:
			return
		}
	}
}

func (s *quicSessionMux) terminalError() error {
	s.mu.Lock()
	err := s.cause
	s.mu.Unlock()
	if err == nil {
		return net.ErrClosed
	}
	return err
}

func (s *quicSessionMux) register(flowID wire.FlowID) (*quicDatagramFlow, error) {
	if flowID == 0 {
		return nil, errors.New("nowhere: zero flow id")
	}
	flow := newQUICDatagramFlow(s, flowID)

	s.mu.Lock()
	if s.closed {
		cause := s.cause
		s.mu.Unlock()
		return nil, cause
	}
	if s.flows[flowID] != nil {
		s.mu.Unlock()
		return nil, errors.New("nowhere: duplicate quic udp flow")
	}
	s.flows[flowID] = flow
	s.startOnce.Do(func() {
		s.started = true
		go s.receiveLoop()
	})
	s.mu.Unlock()
	return flow, nil
}

func (s *quicSessionMux) unregister(flowID wire.FlowID, flow *quicDatagramFlow, cause error) {
	s.mu.Lock()
	if s.flows[flowID] != flow {
		s.mu.Unlock()
		return
	}
	delete(s.flows, flowID)
	s.reassembler.RemoveFlow(flowID)
	s.mu.Unlock()
	flow.finish(cause)
}

func (s *quicSessionMux) receiveLoop() {
	defer close(s.loopDone)
	for {
		receiveCtx, cancel := context.WithTimeout(s.ctx, quicReassemblySweep)
		data, err := s.raw.ReceiveDatagram(receiveCtx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && s.ctx.Err() == nil {
				s.mu.Lock()
				s.reassembler.Expire(time.Now())
				s.mu.Unlock()
				continue
			}
			if s.ctx.Err() != nil {
				return
			}
			s.invalidateRaw(err)
			return
		}
		frame, err := wire.DecodeUDPFrame(data)
		if err != nil {
			continue
		}
		switch frame.Type {
		case wire.UDPFrameTypeData:
			// Unfragmented DATA: deliver immediately (zero-length is legal).
			s.deliver(frame.FlowID, frame.Payload)
		case wire.UDPFrameTypeFragment:
			s.handleFragment(frame.FlowID, frame.Fragment)
		case wire.UDPFrameTypeClose:
			s.closeFlow(frame.FlowID)
		}
	}
}

// deliver hands an already-complete UDP payload to its flow if registered.
func (s *quicSessionMux) deliver(flowID wire.FlowID, payload []byte) {
	s.mu.Lock()
	flow := s.flows[flowID]
	s.mu.Unlock()
	if flow != nil {
		flow.enqueue(bytes.Clone(payload))
	}
}

func (s *quicSessionMux) handleFragment(flowID wire.FlowID, fragment wire.UDPFragment) {
	now := time.Now()
	s.mu.Lock()
	flow := s.flows[flowID]
	if flow == nil || s.closed {
		s.mu.Unlock()
		return
	}
	// Hand the fragment to the wire reassembler (it owns slot/byte/TTL limits,
	// identical-duplicate handling, and metadata-conflict drops).
	owned := wire.UDPFragment{
		PacketID:      fragment.PacketID,
		FragmentIndex: fragment.FragmentIndex,
		FragmentCount: fragment.FragmentCount,
		TotalLen:      fragment.TotalLen,
		Payload:       bytes.Clone(fragment.Payload),
	}
	outcome := s.reassembler.Push(flowID, owned, now)
	s.mu.Unlock()
	if outcome.Done {
		flow.enqueue(outcome.Payload)
	}
}

func (s *quicSessionMux) closeFlow(flowID wire.FlowID) {
	s.mu.Lock()
	flow := s.flows[flowID]
	s.mu.Unlock()
	if flow != nil {
		s.unregister(flowID, flow, io.EOF)
	}
}

func (s *quicSessionMux) invalidateRaw(cause error) {
	if s.invalidation.CompareAndSwap(quicInvalidationNone, quicInvalidationRaw) {
		s.close(cause)
		s.backend.backend.InvalidateSession(s.raw)
		s.finishInvalidation()
		return
	}
	<-s.invalidationDone
}

func (s *quicSessionMux) prepareBackendClose() {
	if s.invalidation.CompareAndSwap(quicInvalidationNone, quicInvalidationBackendClose) {
		s.close(net.ErrClosed)
	}
}

func (s *quicSessionMux) completeBackendClose() {
	if s.invalidation.Load() == quicInvalidationBackendClose {
		s.finishInvalidation()
	}
	<-s.invalidationDone
}

func (s *quicSessionMux) finishInvalidation() {
	s.finishOnce.Do(func() {
		s.backend.remove(s)
		s.invalidation.Store(quicInvalidationFinished)
		close(s.invalidationDone)
	})
}

func (s *quicSessionMux) close(cause error) {
	s.closeOnce.Do(func() {
		if cause == nil || errors.Is(cause, context.Canceled) {
			cause = net.ErrClosed
		}
		s.completeAuthentication(cause)
		s.cancel()

		s.mu.Lock()
		s.closed = true
		s.cause = cause
		flows := make([]*quicDatagramFlow, 0, len(s.flows))
		for _, flow := range s.flows {
			flows = append(flows, flow)
		}
		s.flows = make(map[wire.FlowID]*quicDatagramFlow)
		s.reassembler.Clear()
		s.closeQueue = nil
		started := s.started
		s.mu.Unlock()

		if !started {
			close(s.loopDone)
		}
		for _, flow := range flows {
			flow.finish(cause)
		}
		close(s.done)
	})
}

var _ carrier.QuicSession = (*quicSessionMux)(nil)
var _ carrier.QuicPreparedStream = (*quicAuthPreparedStream)(nil)

type quicDatagramFlow struct {
	session *quicSessionMux
	flowID  wire.FlowID
	packets chan []byte
	done    chan struct{}

	mu         sync.Mutex
	cause      error
	closed     bool
	finishOnce sync.Once
}

func newQUICDatagramFlow(session *quicSessionMux, flowID wire.FlowID) *quicDatagramFlow {
	return &quicDatagramFlow{
		session: session,
		flowID:  flowID,
		packets: make(chan []byte, quicDatagramFlowQueue),
		done:    make(chan struct{}),
	}
}

func (f *quicDatagramFlow) enqueue(payload []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	select {
	case f.packets <- payload:
	default:
	}
}

func (f *quicDatagramFlow) readPacket(ctx context.Context, deadline *datagramDeadline) ([]byte, error) {
	for {
		at, deadlineSignal, deadlineClosed := deadline.snapshot()
		if deadlineClosed {
			return nil, net.ErrClosed
		}
		if deadlineExpired(at) {
			return nil, errDatagramDeadline
		}
		select {
		case payload := <-f.packets:
			if deadline.expired() {
				return nil, errDatagramDeadline
			}
			return payload, nil
		default:
		}
		select {
		case payload := <-f.packets:
			if deadline.expired() {
				return nil, errDatagramDeadline
			}
			return payload, nil
		case <-deadlineSignal:
			continue
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.done:
			select {
			case payload := <-f.packets:
				return payload, nil
			default:
			}
			return nil, f.closeCause()
		}
	}
}

func (f *quicDatagramFlow) closeCause() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cause == nil {
		return io.EOF
	}
	return f.cause
}

func (f *quicDatagramFlow) finish(cause error) {
	f.finishOnce.Do(func() {
		if cause == nil {
			cause = io.EOF
		}
		f.mu.Lock()
		f.closed = true
		f.cause = cause
		close(f.done)
		f.mu.Unlock()
	})
}

func (f *quicDatagramFlow) unregister(cause error) {
	f.session.unregister(f.flowID, f, cause)
}
