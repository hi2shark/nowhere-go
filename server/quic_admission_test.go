package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

func TestServeQUICAdmissionGlobalLimit(t *testing.T) {
	handler, _, observer := newQUICAdmissionTestHandler(t, Limits{
		MaxUnauthenticatedConnections: 2,
		MaxUnauthenticatedPerSource:   2,
	}, time.Second)

	_, cancelFirst, firstDone := startBlockingQUICAdmission(t, handler, udpAddr("192.0.2.1", 1001))
	waitQUICAdmissionActive(t, handler, 1)
	_, cancelSecond, secondDone := startBlockingQUICAdmission(t, handler, udpAddr("192.0.2.2", 1002))
	waitQUICAdmissionActive(t, handler, 2)

	rejected := newQUICAdmissionConn(udpAddr("192.0.2.3", 1003))
	err := waitQUICServeResult(t, serveQUICAsync(handler, context.Background(), rejected))
	if !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("ServeQUIC error = %v, want ErrAdmissionLimit", err)
	}
	if !IsReported(err) {
		t.Fatal("QUIC admission rejection should be reported")
	}
	if got := rejected.acceptCalls.Load(); got != 0 {
		t.Fatalf("rejected QUIC AcceptStream calls = %d, want 0", got)
	}
	if got := rejected.closeCalls.Load(); got != 1 {
		t.Fatalf("rejected QUIC close calls = %d, want 1", got)
	}
	if !observer.hasCode("admission_limited") {
		t.Fatal("missing admission_limited event")
	}

	cancelFirst()
	cancelSecond()
	_ = waitQUICServeResult(t, firstDone)
	_ = waitQUICServeResult(t, secondDone)
	waitQUICAdmissionActive(t, handler, 0)
}

func TestServeQUICAdmissionPerSourceLimit(t *testing.T) {
	handler, _, _ := newQUICAdmissionTestHandler(t, Limits{
		MaxUnauthenticatedConnections: 2,
		MaxUnauthenticatedPerSource:   1,
	}, time.Second)

	_, cancelFirst, firstDone := startBlockingQUICAdmission(t, handler, udpAddr("198.51.100.8", 2001))
	waitQUICAdmissionActive(t, handler, 1)

	rejected := newQUICAdmissionConn(udpAddr("198.51.100.8", 2002))
	err := waitQUICServeResult(t, serveQUICAsync(handler, context.Background(), rejected))
	if !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("ServeQUIC error = %v, want per-source ErrAdmissionLimit", err)
	}
	if got := rejected.acceptCalls.Load(); got != 0 {
		t.Fatalf("rejected QUIC AcceptStream calls = %d, want 0", got)
	}
	if got := handler.admission.active(); got != 1 {
		t.Fatalf("active admission after per-source rejection = %d, want 1", got)
	}

	cancelFirst()
	_ = waitQUICServeResult(t, firstDone)
	waitQUICAdmissionActive(t, handler, 0)
}

func TestServeQUICSharesAdmissionBudgetWithTCP(t *testing.T) {
	handler, _, _ := newQUICAdmissionTestHandler(t, Limits{
		MaxUnauthenticatedConnections: 1,
		MaxUnauthenticatedPerSource:   1,
	}, time.Second)

	_, cancelQUIC, quicDone := startBlockingQUICAdmission(t, handler, udpAddr("203.0.113.10", 3001))
	waitQUICAdmissionActive(t, handler, 1)

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	var handshakeCalled atomic.Bool
	err := handler.ServeTCP(context.Background(), serverConn, tcpAddr("203.0.113.11", 3002), func(context.Context, net.Conn) (net.Conn, error) {
		handshakeCalled.Store(true)
		return nil, errors.New("unexpected handshake")
	}, nil)
	if !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("ServeTCP error = %v, want shared ErrAdmissionLimit", err)
	}
	if handshakeCalled.Load() {
		t.Fatal("TCP handshake ran despite QUIC consuming the shared admission budget")
	}

	cancelQUIC()
	_ = waitQUICServeResult(t, quicDone)
	waitQUICAdmissionActive(t, handler, 0)
}

func TestServeQUICReleasesAdmissionImmediatelyAfterAuthSuccess(t *testing.T) {
	handler, config, _ := newQUICAdmissionTestHandler(t, Limits{
		MaxUnauthenticatedConnections: 1,
		MaxUnauthenticatedPerSource:   1,
	}, time.Second)
	sessionID := wire.SessionID{0xa1}
	auth, err := wire.MakeAuthFrameWithSession("secret", config.EffectiveSpec(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	conn := newQUICAdmissionConn(udpAddr("203.0.113.20", 4001), newQUICAdmissionStream(bytes.NewReader(auth)))
	ctx, cancel := context.WithCancel(context.Background())
	done := serveQUICAsync(handler, ctx, conn)

	waitQUICSession(t, handler, sessionID)
	if got := handler.admission.active(); got != 0 {
		t.Fatalf("admission active after QUIC auth success = %d, want 0", got)
	}
	select {
	case err := <-done:
		t.Fatalf("ServeQUIC returned before session cancellation: %v", err)
	default:
	}

	cancel()
	if err := waitQUICServeResult(t, done); err != nil {
		t.Fatalf("ServeQUIC after authenticated cancellation = %v, want nil", err)
	}
	if got := handler.admission.active(); got != 0 {
		t.Fatalf("admission active after deferred release = %d, want 0", got)
	}
}

func TestServeQUICReleasesAdmissionAfterAuthFailure(t *testing.T) {
	handler, _, _ := newQUICAdmissionTestHandler(t, Limits{
		MaxUnauthenticatedConnections: 1,
		MaxUnauthenticatedPerSource:   1,
	}, 40*time.Millisecond)
	handler.randRead = func([]byte) (int, error) { return 0, errors.New("deterministic auth deadline") }
	reader := newBlockingQUICAdmissionReader()
	t.Cleanup(reader.Release)
	conn := newQUICAdmissionConn(udpAddr("203.0.113.30", 5001), newQUICAdmissionStream(reader))
	done := serveQUICAsync(handler, context.Background(), conn)

	waitQUICSignal(t, reader.started, "QUIC auth did not start")
	waitQUICAdmissionActive(t, handler, 1)
	reader.Release()
	if err := waitQUICServeResult(t, done); err == nil {
		t.Fatal("ServeQUIC auth failure returned nil")
	}
	waitQUICAdmissionActive(t, handler, 0)
}

func TestServeQUICReleasesAdmissionAfterCancellationAndShutdown(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		handler, _, _ := newQUICAdmissionTestHandler(t, Limits{
			MaxUnauthenticatedConnections: 1,
			MaxUnauthenticatedPerSource:   1,
		}, time.Second)
		_, cancel, done := startBlockingQUICAdmission(t, handler, udpAddr("203.0.113.40", 6001))
		waitQUICAdmissionActive(t, handler, 1)

		cancel()
		_ = waitQUICServeResult(t, done)
		waitQUICAdmissionActive(t, handler, 0)
	})

	t.Run("shutdown", func(t *testing.T) {
		handler, _, _ := newQUICAdmissionTestHandler(t, Limits{
			MaxUnauthenticatedConnections: 1,
			MaxUnauthenticatedPerSource:   1,
		}, time.Second)
		_, _, done := startBlockingQUICAdmission(t, handler, udpAddr("203.0.113.41", 6002))
		waitQUICAdmissionActive(t, handler, 1)

		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
		defer cancelShutdown()
		if err := handler.Shutdown(shutdownCtx); err != nil {
			t.Fatalf("Shutdown = %v", err)
		}
		_ = waitQUICServeResult(t, done)
		waitQUICAdmissionActive(t, handler, 0)
		if err := handler.Shutdown(context.Background()); err != nil {
			t.Fatalf("second Shutdown = %v", err)
		}
	})
}

func newQUICAdmissionTestHandler(t *testing.T, limits Limits, authTimeout time.Duration) (*Handler, *Config, *recordingObserver) {
	t.Helper()
	config, err := NewConfig(ConfigOptions{
		Password: "secret",
		Networks: []Network{NetworkTCP, NetworkUDP},
		Timeouts: Timeouts{Auth: authTimeout, Shutdown: time.Second},
		Limits:   limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	observer := &recordingObserver{}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}, Observer: observer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = handler.Shutdown(ctx)
	})
	return handler, config, observer
}

func startBlockingQUICAdmission(t *testing.T, handler *Handler, remote net.Addr) (*quicAdmissionConn, context.CancelFunc, <-chan error) {
	t.Helper()
	conn := newQUICAdmissionConn(remote)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = conn.Close() })
	return conn, cancel, serveQUICAsync(handler, ctx, conn)
}

func serveQUICAsync(handler *Handler, ctx context.Context, conn QuicConn) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- handler.ServeQUIC(ctx, conn)
	}()
	return done
}

func waitQUICServeResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("ServeQUIC did not return")
		return nil
	}
}

func waitQUICAdmissionActive(t *testing.T, handler *Handler, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := handler.admission.active(); got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active QUIC admission = %d, want %d", handler.admission.active(), want)
}

func waitQUICSession(t *testing.T, handler *Handler, sessionID wire.SessionID) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if handler.sessions.Current(sessionID) != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("authenticated QUIC session was not registered")
}

func waitQUICSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func udpAddr(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

func tcpAddr(ip string, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

type quicAdmissionConn struct {
	remote net.Addr

	mu      sync.Mutex
	streams []QuicStream

	closed      chan struct{}
	closeOnce   sync.Once
	acceptCalls atomic.Int32
	closeCalls  atomic.Int32
}

func newQUICAdmissionConn(remote net.Addr, streams ...QuicStream) *quicAdmissionConn {
	return &quicAdmissionConn{
		remote:  remote,
		streams: append([]QuicStream(nil), streams...),
		closed:  make(chan struct{}),
	}
}

func (c *quicAdmissionConn) AcceptStream(ctx context.Context) (QuicStream, error) {
	c.acceptCalls.Add(1)
	c.mu.Lock()
	if len(c.streams) > 0 {
		stream := c.streams[0]
		c.streams = c.streams[1:]
		c.mu.Unlock()
		return stream, nil
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, net.ErrClosed
	}
}

func (c *quicAdmissionConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, net.ErrClosed
	}
}

func (*quicAdmissionConn) SendDatagram([]byte) error { return nil }

func (c *quicAdmissionConn) CloseWithError(uint64, string) error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *quicAdmissionConn) Close() error {
	return c.CloseWithError(uint64(wire.CloseErrCodeOK), "")
}

func (*quicAdmissionConn) Context() context.Context { return context.Background() }
func (*quicAdmissionConn) LocalAddr() net.Addr      { return &net.UDPAddr{} }
func (c *quicAdmissionConn) RemoteAddr() net.Addr   { return c.remote }

type quicAdmissionStream struct {
	reader io.Reader
}

func newQUICAdmissionStream(reader io.Reader) *quicAdmissionStream {
	return &quicAdmissionStream{reader: reader}
}

func (s *quicAdmissionStream) Read(buffer []byte) (int, error) { return s.reader.Read(buffer) }
func (*quicAdmissionStream) Write(buffer []byte) (int, error)  { return len(buffer), nil }
func (*quicAdmissionStream) Close() error                      { return nil }
func (*quicAdmissionStream) SetDeadline(time.Time) error       { return nil }
func (*quicAdmissionStream) SetReadDeadline(time.Time) error   { return nil }
func (*quicAdmissionStream) SetWriteDeadline(time.Time) error  { return nil }
func (*quicAdmissionStream) CancelRead(uint64)                 {}
func (*quicAdmissionStream) CancelWrite(uint64)                {}

type blockingQUICAdmissionReader struct {
	started     chan struct{}
	release     chan struct{}
	startedOnce sync.Once
	releaseOnce sync.Once
}

func newBlockingQUICAdmissionReader() *blockingQUICAdmissionReader {
	return &blockingQUICAdmissionReader{started: make(chan struct{}), release: make(chan struct{})}
}

func (r *blockingQUICAdmissionReader) Read([]byte) (int, error) {
	r.startedOnce.Do(func() { close(r.started) })
	<-r.release
	return 0, io.EOF
}

func (r *blockingQUICAdmissionReader) Release() {
	r.releaseOnce.Do(func() { close(r.release) })
}

var (
	_ QuicConn   = (*quicAdmissionConn)(nil)
	_ QuicStream = (*quicAdmissionStream)(nil)
)
