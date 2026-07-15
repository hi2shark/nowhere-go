package bundle

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestQUICQueuedWriteDeadlineCancelsOnlyQueuedRequest(t *testing.T) {
	raw := newDeadlineLifecycleSession(true)
	backend := newDeadlineLifecycleBackend(raw)
	managed := newQUICMuxBackend(backend)
	t.Cleanup(func() { _ = managed.Close() })

	sessionValue, err := managed.AcquireSession(context.Background())
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	session := sessionValue.(*quicSessionMux)
	first := newQUICSendHandle(&quicPreparedStream{session: session, id: 301}, 301)
	firstResult := make(chan error, 1)
	go func() {
		_, err := (&quicLaneUplink{prep: first, flowID: 301}).WritePacket([]byte("first"))
		firstResult <- err
	}()
	awaitDeadlineSignal(t, raw.firstSendStarted, "first native SendDatagram")

	queued := newQUICSendHandle(&quicPreparedStream{session: session, id: 302}, 302)
	queuedLane := &quicLaneUplink{prep: queued, flowID: 302}
	queuedResult := make(chan error, 1)
	go func() {
		_, err := queuedLane.WritePacket([]byte("queued"))
		queuedResult <- err
	}()
	awaitSendQueueLength(t, session, 1)
	if err := queuedLane.SetWriteDeadline(time.Now()); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	assertDeadlineResult(t, queuedResult, "queued WritePacket")
	if got := backend.invalidationCount(); got != 0 {
		t.Fatalf("queued timeout invalidated physical session %d times, want 0", got)
	}

	raw.releaseFirstSend()
	awaitNoError(t, firstResult, "first WritePacket")

	third := newQUICSendHandle(&quicPreparedStream{session: session, id: 303}, 303)
	thirdResult := make(chan error, 1)
	go func() {
		_, err := (&quicLaneUplink{prep: third, flowID: 303}).WritePacket([]byte("third"))
		thirdResult <- err
	}()
	awaitNoError(t, thirdResult, "third WritePacket")
	if got := raw.sentFlowIDs(); !equalFlowIDs(got, []uint64{301, 303}) {
		t.Fatalf("native flow IDs = %v, want [301 303] (queued request skipped)", got)
	}
}

func TestQUICActiveWriteDeadlineUsesNeutralSessionCauseAndReplacement(t *testing.T) {
	firstRaw := newDeadlineLifecycleSession(true)
	replacementRaw := newDeadlineLifecycleSession(false)
	backend := newDeadlineLifecycleBackend(firstRaw, replacementRaw)
	managed := newQUICMuxBackend(backend)
	t.Cleanup(func() { _ = managed.Close() })

	sessionValue, err := managed.AcquireSession(context.Background())
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	session := sessionValue.(*quicSessionMux)
	unrelated, err := session.register(401)
	if err != nil {
		t.Fatalf("register unrelated flow: %v", err)
	}

	trigger := newQUICSendHandle(&quicPreparedStream{session: session, id: 402}, 402)
	triggerLane := &quicLaneUplink{prep: trigger, flowID: 402}
	triggerResult := make(chan error, 1)
	go func() {
		_, err := triggerLane.WritePacket([]byte("blocked"))
		triggerResult <- err
	}()
	awaitDeadlineSignal(t, firstRaw.firstSendStarted, "active native SendDatagram")
	if err := triggerLane.SetWriteDeadline(time.Now()); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	assertDeadlineResult(t, triggerResult, "active WritePacket")
	if got := backend.invalidationCount(); got != 1 {
		t.Fatalf("active timeout invalidations = %d, want 1", got)
	}
	if _, err := unrelated.readPacket(context.Background(), nil); !errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("unrelated flow error = %v, want neutral net.ErrClosed", err)
	}

	replacementValue, err := managed.AcquireSession(context.Background())
	if err != nil {
		t.Fatalf("AcquireSession replacement: %v", err)
	}
	if replacementValue == session {
		t.Fatal("AcquireSession reused invalidated mux")
	}
	replacement := replacementValue.(*quicSessionMux)
	next := newQUICSendHandle(&quicPreparedStream{session: replacement, id: 403}, 403)
	if _, err := (&quicLaneUplink{prep: next, flowID: 403}).WritePacket([]byte("replacement")); err != nil {
		t.Fatalf("replacement WritePacket: %v", err)
	}
	if got := replacementRaw.sentFlowIDs(); !equalFlowIDs(got, []uint64{403}) {
		t.Fatalf("replacement native flow IDs = %v, want [403]", got)
	}
}

func TestDatagramDeadlineTerminalLifecycle(t *testing.T) {
	deadline := newDatagramDeadline()
	if err := deadline.set(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("initial set: %v", err)
	}
	_, firstSignal, closed := deadline.snapshot()
	if closed {
		t.Fatal("initial deadline is closed")
	}
	deadline.mu.Lock()
	firstTimer := deadline.timer
	deadline.mu.Unlock()
	if firstTimer == nil {
		t.Fatal("initial deadline did not create a timer")
	}

	if err := deadline.set(time.Now().Add(2 * time.Hour)); err != nil {
		t.Fatalf("replacement set: %v", err)
	}
	awaitDeadlineSignal(t, firstSignal, "replaced deadline signal")
	if firstTimer.Stop() {
		t.Fatal("replaced deadline left the old timer active")
	}

	if err := deadline.set(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	deadline.mu.Lock()
	clearedTimer := deadline.timer
	deadline.mu.Unlock()
	if clearedTimer != nil {
		t.Fatal("clear deadline left a timer armed")
	}

	deadline.close()
	at, terminalSignal, closed := deadline.snapshot()
	if !closed {
		t.Fatal("close did not latch terminal state")
	}
	if !at.IsZero() {
		t.Fatalf("closed deadline time = %v, want zero", at)
	}
	awaitDeadlineSignal(t, terminalSignal, "terminal deadline signal")
	if err := deadline.set(time.Now().Add(time.Hour)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("set after close = %v, want net.ErrClosed", err)
	}
	deadline.mu.Lock()
	terminalTimer := deadline.timer
	deadline.mu.Unlock()
	if terminalTimer != nil {
		t.Fatal("set after close re-armed a timer")
	}
}

func TestDatagramDeadlineSetCloseLinearizable(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		deadline := newDatagramDeadline()
		start := make(chan struct{})
		setResult := make(chan error, 1)
		closeDone := make(chan struct{})
		go func() {
			<-start
			setResult <- deadline.set(time.Now().Add(time.Hour))
		}()
		go func() {
			<-start
			deadline.close()
			close(closeDone)
		}()
		close(start)
		setErr := <-setResult
		<-closeDone
		if setErr != nil && !errors.Is(setErr, net.ErrClosed) {
			t.Fatalf("iteration %d set error = %v", iteration, setErr)
		}
		_, signal, closed := deadline.snapshot()
		if !closed {
			t.Fatalf("iteration %d deadline is not terminal", iteration)
		}
		awaitDeadlineSignal(t, signal, "concurrent terminal deadline signal")
		deadline.mu.Lock()
		timer := deadline.timer
		deadline.mu.Unlock()
		if timer != nil {
			t.Fatalf("iteration %d left a timer armed", iteration)
		}
		if err := deadline.set(time.Time{}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("iteration %d post-close set = %v, want net.ErrClosed", iteration, err)
		}
	}
}

func TestQUICDeadlineSettersRejectClosedHandles(t *testing.T) {
	handle := newQSessionHandle(nil, nil, 0, nil)
	packetConn := &quicPacketConn{session: handle}
	if err := packetConn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for name, set := range map[string]func(time.Time) error{
		"SetReadDeadline":  packetConn.SetReadDeadline,
		"SetWriteDeadline": packetConn.SetWriteDeadline,
		"SetDeadline":      packetConn.SetDeadline,
	} {
		if err := set(time.Now().Add(time.Hour)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("%s after Close = %v, want net.ErrClosed", name, err)
		}
	}

	if err := (&quicLaneUplink{prep: handle}).SetWriteDeadline(time.Now().Add(time.Hour)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("mixed uplink SetWriteDeadline after Close = %v, want net.ErrClosed", err)
	}
	if err := (&quicLaneDownlink{prep: handle}).SetReadDeadline(time.Now().Add(time.Hour)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("mixed downlink SetReadDeadline after Close = %v, want net.ErrClosed", err)
	}
}

func TestDatagramDeadlineTerminalSnapshotUnblocksOperation(t *testing.T) {
	deadline := newDatagramDeadline()
	deadline.close()
	flow := newQUICDatagramFlow(nil, 501)
	result := make(chan error, 1)
	go func() {
		_, err := flow.readPacket(context.Background(), deadline)
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("read after deadline close = %v, want net.ErrClosed", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("read spun or blocked after terminal deadline close")
	}
}

func awaitSendQueueLength(t *testing.T, session *quicSessionMux, want int) {
	t.Helper()
	deadline := time.Now().Add(250 * time.Millisecond)
	for len(session.sendQueue) != want {
		if time.Now().After(deadline) {
			t.Fatalf("send queue length = %d, want %d", len(session.sendQueue), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func awaitNoError(t *testing.T, result <-chan error, operation string) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func equalFlowIDs(got, want []uint64) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

type deadlineLifecycleSession struct {
	blockFirst       bool
	firstSendStarted chan struct{}
	firstSendRelease chan struct{}
	startOnce        sync.Once
	releaseOnce      sync.Once

	mu          sync.Mutex
	flowIDs     []uint64
	invalidated bool
}

func newDeadlineLifecycleSession(blockFirst bool) *deadlineLifecycleSession {
	return &deadlineLifecycleSession{
		blockFirst:       blockFirst,
		firstSendStarted: make(chan struct{}),
		firstSendRelease: make(chan struct{}),
	}
}

func (*deadlineLifecycleSession) PrepareStream(context.Context) (quic.PreparedStream, error) {
	return nil, errors.New("test: unexpected PrepareStream")
}
func (s *deadlineLifecycleSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*deadlineLifecycleSession) CurrentMaxDatagramSize() int { return nowuDataHeaderLen + 64 }
func (s *deadlineLifecycleSession) SendDatagram(frame []byte) error {
	decoded, err := wire.DecodeUDPFrame(frame)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.flowIDs = append(s.flowIDs, decoded.FlowID)
	index := len(s.flowIDs)
	s.mu.Unlock()
	if s.blockFirst && index == 1 {
		s.startOnce.Do(func() { close(s.firstSendStarted) })
		<-s.firstSendRelease
	}
	s.mu.Lock()
	invalidated := s.invalidated
	s.mu.Unlock()
	if invalidated {
		return net.ErrClosed
	}
	return nil
}
func (*deadlineLifecycleSession) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (s *deadlineLifecycleSession) invalidate() {
	s.mu.Lock()
	s.invalidated = true
	s.mu.Unlock()
	s.releaseFirstSend()
}
func (s *deadlineLifecycleSession) releaseFirstSend() {
	s.releaseOnce.Do(func() { close(s.firstSendRelease) })
}
func (s *deadlineLifecycleSession) sentFlowIDs() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint64(nil), s.flowIDs...)
}

type deadlineLifecycleBackend struct {
	mu            sync.Mutex
	sessions      []*deadlineLifecycleSession
	current       int
	invalidations int
	closed        bool
}

func newDeadlineLifecycleBackend(sessions ...*deadlineLifecycleSession) *deadlineLifecycleBackend {
	return &deadlineLifecycleBackend{sessions: sessions}
}

func (*deadlineLifecycleBackend) SetSessionID(wire.SessionID) {}
func (b *deadlineLifecycleBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, net.ErrClosed
	}
	if b.current >= len(b.sessions) {
		return nil, errors.New("test: no replacement session")
	}
	return b.sessions[b.current], nil
}
func (b *deadlineLifecycleBackend) InvalidateSession(session carrier.QuicSession) {
	raw := session.(*deadlineLifecycleSession)
	b.mu.Lock()
	b.invalidations++
	if b.current < len(b.sessions) && b.sessions[b.current] == raw {
		b.current++
	}
	b.mu.Unlock()
	raw.invalidate()
}
func (b *deadlineLifecycleBackend) Close() error {
	b.mu.Lock()
	b.closed = true
	sessions := append([]*deadlineLifecycleSession(nil), b.sessions...)
	b.mu.Unlock()
	for _, session := range sessions {
		session.invalidate()
	}
	return nil
}
func (b *deadlineLifecycleBackend) invalidationCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.invalidations
}

var _ quic.Backend = (*deadlineLifecycleBackend)(nil)
