package bundle

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestQUICUDPCloseQueuePressureReliablyReleasesRemoteFlows(t *testing.T) {
	raw := newClosePressureSession()
	backend := &closePressureBackend{session: raw}
	managed := newQUICMuxBackend(backend)
	t.Cleanup(func() {
		raw.release()
		_ = managed.Close()
	})

	sessionValue, err := managed.AcquireSession(context.Background())
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	session := sessionValue.(*quicSessionMux)

	first := newQUICSendHandle(&quicPreparedStream{session: session, id: 1}, 1)
	firstWrite := make(chan error, 1)
	go func() {
		_, err := (&quicLaneUplink{prep: first, flowID: 1}).WritePacket([]byte("blocked"))
		firstWrite <- err
	}()
	closePressureAwait(t, raw.sendStarted, "blocked send owner")

	second := newQUICSendHandle(&quicPreparedStream{session: session, id: 2}, 2)
	secondWrite := make(chan error, 1)
	go func() {
		_, err := (&quicLaneUplink{prep: second, flowID: 2}).WritePacket([]byte("queued"))
		secondWrite <- err
	}()
	deadline := time.Now().Add(time.Second)
	for len(session.sendQueue) != cap(session.sendQueue) {
		if time.Now().After(deadline) {
			t.Fatalf("send queue length = %d, want %d", len(session.sendQueue), cap(session.sendQueue))
		}
		time.Sleep(time.Millisecond)
	}

	const closeCount = 300
	for index := 0; index < closeCount; index++ {
		flowID := uint64(1000 + index)
		raw.registerRemote(flowID)
		handle := newQUICSendHandle(&quicPreparedStream{session: session, id: flowID}, flowID)
		closed := make(chan error, 1)
		go func() { closed <- handle.closePacket() }()
		select {
		case err := <-closed:
			if err != nil {
				t.Fatalf("close flow %d: %v", flowID, err)
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatalf("close flow %d blocked behind full send queue", flowID)
		}
	}

	raw.release()
	closePressureAwaitError(t, firstWrite, "first DATA")
	closePressureAwaitError(t, secondWrite, "second DATA")

	deadline = time.Now().Add(3 * time.Second)
	for {
		remaining := raw.remoteCount()
		if remaining == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("remote active flows/permits after CLOSE drain = %d, want 0", remaining)
		}
		time.Sleep(time.Millisecond)
	}
	if got := raw.closeFrames(); got != closeCount {
		t.Fatalf("remote CLOSE frames = %d, want %d", got, closeCount)
	}
}

func closePressureAwait(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func closePressureAwaitError(t *testing.T, result <-chan error, operation string) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

type closePressureSession struct {
	sendStarted chan struct{}
	releaseSend chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once

	mu          sync.Mutex
	remoteFlows map[uint64]struct{}
	closes      int
}

func newClosePressureSession() *closePressureSession {
	return &closePressureSession{
		sendStarted: make(chan struct{}),
		releaseSend: make(chan struct{}),
		remoteFlows: make(map[uint64]struct{}),
	}
}

func (*closePressureSession) PrepareStream(context.Context) (quic.PreparedStream, error) {
	return nil, errors.New("test: unexpected PrepareStream")
}

func (*closePressureSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*closePressureSession) CurrentMaxDatagramSize() int { return nowuDataHeaderLen + 64 }

func (s *closePressureSession) SendDatagram(frame []byte) error {
	s.startOnce.Do(func() { close(s.sendStarted) })
	<-s.releaseSend
	decoded, err := wire.DecodeUDPFrame(frame)
	if err != nil {
		return err
	}
	if decoded.Type == wire.UDPFrameClose {
		s.mu.Lock()
		delete(s.remoteFlows, decoded.FlowID)
		s.closes++
		s.mu.Unlock()
	}
	return nil
}

func (*closePressureSession) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (s *closePressureSession) release() {
	s.releaseOnce.Do(func() { close(s.releaseSend) })
}

func (s *closePressureSession) registerRemote(flowID uint64) {
	s.mu.Lock()
	s.remoteFlows[flowID] = struct{}{}
	s.mu.Unlock()
}

func (s *closePressureSession) remoteCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.remoteFlows)
}

func (s *closePressureSession) closeFrames() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

var _ carrier.QuicSession = (*closePressureSession)(nil)

type closePressureBackend struct {
	session *closePressureSession
}

func (*closePressureBackend) SetSessionID(wire.SessionID) {}
func (b *closePressureBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return b.session, nil
}
func (*closePressureBackend) InvalidateSession(carrier.QuicSession) {}
func (b *closePressureBackend) Close() error {
	b.session.release()
	return nil
}

var _ carrier.QuicBackend = (*closePressureBackend)(nil)

func TestQUICUDPCloseSendFailureInvalidatesSession(t *testing.T) {
	sendErr := errors.New("test: CLOSE send failed")
	raw := &closeFailureSession{sendErr: sendErr, sent: make(chan struct{})}
	backend := &closeFailureBackend{session: raw}
	managed := newQUICMuxBackend(backend)
	t.Cleanup(func() { _ = managed.Close() })

	sessionValue, err := managed.AcquireSession(context.Background())
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	session := sessionValue.(*quicSessionMux)
	handle := newQUICSendHandle(&quicPreparedStream{session: session, id: 91}, 91)
	if err := handle.closePacket(); err != nil {
		t.Fatalf("queue CLOSE: %v", err)
	}
	closePressureAwait(t, raw.sent, "failed raw CLOSE send")
	closePressureAwait(t, session.done, "session invalidation")
	closePressureAwait(t, session.sendLoopDone, "send loop termination")
	if err := session.terminalError(); !errors.Is(err, sendErr) {
		t.Fatalf("terminal error = %v, want %v", err, sendErr)
	}
	if got := backend.invalidationCount(); got != 1 {
		t.Fatalf("raw invalidations = %d, want 1", got)
	}
	if err := session.SendDatagram([]byte("after failure")); !errors.Is(err, sendErr) {
		t.Fatalf("SendDatagram after CLOSE failure = %v, want %v", err, sendErr)
	}
}

type closeFailureSession struct {
	sendErr error
	sent    chan struct{}
	once    sync.Once
}

func (*closeFailureSession) PrepareStream(context.Context) (quic.PreparedStream, error) {
	return nil, errors.New("test: unexpected PrepareStream")
}
func (*closeFailureSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*closeFailureSession) CurrentMaxDatagramSize() int { return nowuDataHeaderLen + 64 }
func (s *closeFailureSession) SendDatagram([]byte) error {
	s.once.Do(func() { close(s.sent) })
	return s.sendErr
}
func (*closeFailureSession) LocalAddr() net.Addr { return &net.UDPAddr{} }

var _ carrier.QuicSession = (*closeFailureSession)(nil)

type closeFailureBackend struct {
	session *closeFailureSession
	mu      sync.Mutex
	count   int
}

func (*closeFailureBackend) SetSessionID(wire.SessionID) {}
func (b *closeFailureBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return b.session, nil
}
func (b *closeFailureBackend) InvalidateSession(carrier.QuicSession) {
	b.mu.Lock()
	b.count++
	b.mu.Unlock()
}
func (*closeFailureBackend) Close() error { return nil }
func (b *closeFailureBackend) invalidationCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.count
}

var _ carrier.QuicBackend = (*closeFailureBackend)(nil)
