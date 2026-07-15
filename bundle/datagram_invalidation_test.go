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

func TestQUICReceiveFailureInvalidatesBlockedSendOnce(t *testing.T) {
	const rounds = 3
	backend := newTerminalReceiveBackend(rounds + 1)
	managed := newQUICMuxBackend(backend)
	t.Cleanup(func() {
		backend.releaseAll()
		_ = managed.Close()
	})

	sessionValue, err := managed.AcquireSession(context.Background())
	if err != nil {
		t.Fatalf("initial AcquireSession: %v", err)
	}
	for round := 0; round < rounds; round++ {
		raw := backend.raw(round)
		session := sessionValue.(*quicSessionMux)
		if session.raw != raw {
			t.Fatalf("round %d raw session = %p, want %p", round, session.raw, raw)
		}

		flowID := uint64(round + 1)
		prepared := &quicPreparedStream{session: session, id: flowID}
		pc := newQUICPacketConn(prepared, nil, "example.com:53")
		writeResult := make(chan error, 1)
		go func() {
			_, err := pc.WriteTo([]byte("blocked"), nil)
			writeResult <- err
		}()
		task5AwaitSignal(t, raw.sendStarted, "terminal-failure SendDatagram")
		task5AwaitSignal(t, raw.invalidateStarted, "raw session invalidation")

		select {
		case err := <-writeResult:
			if !errors.Is(err, raw.terminalErr) && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("round %d WriteTo error = %v, want terminal or closed error", round, err)
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatalf("round %d WriteTo remained blocked after terminal receive failure", round)
		}

		explicitDone := make(chan struct{})
		go func() {
			managed.InvalidateSession(session)
			close(explicitDone)
		}()
		acquired := make(chan carrier.QuicSession, 1)
		acquireErr := make(chan error, 1)
		go func() {
			next, err := managed.AcquireSession(context.Background())
			if err != nil {
				acquireErr <- err
				return
			}
			acquired <- next
		}()
		select {
		case next := <-acquired:
			t.Fatalf("round %d AcquireSession returned %p before invalidation completed", round, next)
		case err := <-acquireErr:
			t.Fatalf("round %d AcquireSession before invalidation: %v", round, err)
		case <-time.After(20 * time.Millisecond):
		}

		raw.allowInvalidation()
		select {
		case <-explicitDone:
		case <-time.After(250 * time.Millisecond):
			t.Fatalf("round %d explicit InvalidateSession deadlocked", round)
		}
		select {
		case <-session.sendLoopDone:
		case <-time.After(250 * time.Millisecond):
			t.Fatalf("round %d send loop did not stop", round)
		}
		if got := backend.invalidationCount(raw); got != 1 {
			t.Fatalf("round %d raw invalidations = %d, want 1", round, got)
		}

		secondExplicitDone := make(chan struct{})
		go func() {
			managed.InvalidateSession(session)
			close(secondExplicitDone)
		}()
		select {
		case <-secondExplicitDone:
		case <-time.After(250 * time.Millisecond):
			t.Fatalf("round %d repeated InvalidateSession deadlocked", round)
		}
		if got := backend.invalidationCount(raw); got != 1 {
			t.Fatalf("round %d repeated raw invalidations = %d, want 1", round, got)
		}

		select {
		case err := <-acquireErr:
			t.Fatalf("round %d AcquireSession after invalidation: %v", round, err)
		case sessionValue = <-acquired:
		case <-time.After(250 * time.Millisecond):
			t.Fatalf("round %d AcquireSession did not return a replacement", round)
		}
		if sessionValue == session {
			t.Fatalf("round %d reused closed mux", round)
		}
		managed.mu.Lock()
		_, oldRegistered := managed.sessions[raw]
		activeSessions := len(managed.sessions)
		managed.mu.Unlock()
		if oldRegistered || activeSessions != 1 {
			t.Fatalf("round %d mux map: old=%v active=%d, want false/1", round, oldRegistered, activeSessions)
		}
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- managed.Close() }()
	task5AwaitCloseResult(t, closeResult, "terminal receive backend Close")
	if err := managed.Close(); err != nil {
		t.Fatalf("second backend Close: %v", err)
	}
}

type terminalReceiveSession struct {
	terminalErr       error
	sendStarted       chan struct{}
	invalidateStarted chan struct{}
	allowInvalidateCh chan struct{}
	sendReleased      chan struct{}
	sendOnce          sync.Once
	invalidateOnce    sync.Once
	allowOnce         sync.Once
	releaseOnce       sync.Once
}

func newTerminalReceiveSession(index int) *terminalReceiveSession {
	return &terminalReceiveSession{
		terminalErr:       errors.New("test: terminal receive failure"),
		sendStarted:       make(chan struct{}),
		invalidateStarted: make(chan struct{}),
		allowInvalidateCh: make(chan struct{}),
		sendReleased:      make(chan struct{}),
	}
}

func (*terminalReceiveSession) PrepareStream(context.Context) (quic.PreparedStream, error) {
	return nil, errors.New("test: unexpected PrepareStream")
}

func (s *terminalReceiveSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-s.sendStarted:
		return nil, s.terminalErr
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (*terminalReceiveSession) CurrentMaxDatagramSize() int { return nowuDataHeaderLen + 64 }

func (s *terminalReceiveSession) SendDatagram([]byte) error {
	s.sendOnce.Do(func() { close(s.sendStarted) })
	<-s.sendReleased
	return net.ErrClosed
}

func (*terminalReceiveSession) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (s *terminalReceiveSession) beginInvalidation() {
	s.invalidateOnce.Do(func() { close(s.invalidateStarted) })
	<-s.allowInvalidateCh
	s.release()
}

func (s *terminalReceiveSession) allowInvalidation() {
	s.allowOnce.Do(func() { close(s.allowInvalidateCh) })
}

func (s *terminalReceiveSession) release() {
	s.releaseOnce.Do(func() { close(s.sendReleased) })
}

var _ carrier.QuicSession = (*terminalReceiveSession)(nil)

type terminalReceiveBackend struct {
	mu            sync.Mutex
	sessions      []*terminalReceiveSession
	current       int
	invalidations map[*terminalReceiveSession]int
	closed        bool
}

func newTerminalReceiveBackend(count int) *terminalReceiveBackend {
	backend := &terminalReceiveBackend{
		sessions:      make([]*terminalReceiveSession, count),
		invalidations: make(map[*terminalReceiveSession]int),
	}
	for i := range backend.sessions {
		backend.sessions[i] = newTerminalReceiveSession(i)
	}
	return backend
}

func (*terminalReceiveBackend) SetSessionID(wire.SessionID) {}

func (b *terminalReceiveBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, net.ErrClosed
	}
	if b.current >= len(b.sessions) {
		return nil, errors.New("test: no replacement raw session")
	}
	return b.sessions[b.current], nil
}

func (b *terminalReceiveBackend) InvalidateSession(session carrier.QuicSession) {
	raw := session.(*terminalReceiveSession)
	b.mu.Lock()
	b.invalidations[raw]++
	b.mu.Unlock()
	raw.beginInvalidation()
	b.mu.Lock()
	if b.current < len(b.sessions) && b.sessions[b.current] == raw {
		b.current++
	}
	b.mu.Unlock()
}

func (b *terminalReceiveBackend) Close() error {
	b.mu.Lock()
	b.closed = true
	sessions := append([]*terminalReceiveSession(nil), b.sessions...)
	b.mu.Unlock()
	for _, session := range sessions {
		session.allowInvalidation()
		session.release()
	}
	return nil
}

func (b *terminalReceiveBackend) raw(index int) *terminalReceiveSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sessions[index]
}

func (b *terminalReceiveBackend) invalidationCount(raw *terminalReceiveSession) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.invalidations[raw]
}

func (b *terminalReceiveBackend) releaseAll() {
	b.mu.Lock()
	sessions := append([]*terminalReceiveSession(nil), b.sessions...)
	b.mu.Unlock()
	for _, session := range sessions {
		session.allowInvalidation()
		session.release()
	}
}

var _ carrier.QuicBackend = (*terminalReceiveBackend)(nil)
