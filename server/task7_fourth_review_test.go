package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

func TestTask7FourthReviewQUICAbortContractUnblocksAndCoreJoins(t *testing.T) {
	conn := newTask7FourthAbortContractQuicConn()
	acceptDone := make(chan error, 1)
	go func() {
		_, err := conn.AcceptStream(context.Background())
		acceptDone <- err
	}()
	receiveDone := make(chan error, 1)
	go func() {
		_, err := conn.ReceiveDatagram(context.Background())
		receiveDone <- err
	}()
	waitTask7FourthSignal(t, conn.acceptEntered, "AcceptStream did not block")
	waitTask7FourthSignal(t, conn.receiveEntered, "ReceiveDatagram did not block")

	bound := &quicUDPDownlinkBound{
		flowID: 1,
		base: newQUICUDPDownlink(nil, conn.SendDatagram, func() int { return 1200 }, func(error) {
			_ = conn.CloseWithError(uint64(wire.CloseErrCodeOK), "abort")
		}),
	}
	gracefulDone := make(chan error, 1)
	go func() { gracefulDone <- bound.WriteClose() }()
	waitTask7FourthSignal(t, conn.sendEntered, "typed CLOSE did not enter SendDatagram")
	forcedDone := make(chan error, 1)
	go func() { forcedDone <- bound.Close() }()

	waitTask7FourthSignal(t, conn.closeReturned, "CloseWithError waited for concurrent QUIC operations")
	if err := waitTask7FourthError(t, acceptDone, "AcceptStream did not unblock after CloseWithError"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("AcceptStream = %v, want net.ErrClosed", err)
	}
	if err := waitTask7FourthError(t, receiveDone, "ReceiveDatagram did not unblock after CloseWithError"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReceiveDatagram = %v, want net.ErrClosed", err)
	}
	waitTask7FourthSignal(t, conn.sendObservedAbort, "SendDatagram did not observe physical abort")
	select {
	case err := <-gracefulDone:
		t.Fatalf("graceful terminal returned before joining SendDatagram: %v", err)
	default:
	}
	select {
	case err := <-forcedDone:
		t.Fatalf("forced terminal returned before joining SendDatagram: %v", err)
	default:
	}

	close(conn.allowSendReturn)
	if err := waitTask7FourthError(t, gracefulDone, "graceful terminal did not join SendDatagram"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("graceful terminal = %v, want net.ErrClosed", err)
	}
	if err := waitTask7FourthError(t, forcedDone, "forced terminal did not join SendDatagram"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("forced terminal = %v, want net.ErrClosed", err)
	}
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("CloseWithError calls = %d, want 1", got)
	}
}

func TestTask7FourthReviewServeTCPTransfersParentCancellationToRetainedRoute(t *testing.T) {
	routed := make(chan net.PacketConn, 1)
	handler, config := newFlowTestHandler(t, upstreamFuncs{
		packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
			if err := readiness.Ready(); err != nil {
				return err
			}
			routed <- pc
			return nil
		},
	}, Timeouts{Auth: time.Minute, TLSHandshake: time.Minute, RequestIdle: time.Minute, UDPIdle: time.Minute, Shutdown: 50 * time.Millisecond})

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- handler.ServeTCP(parent, serverConn, serverConn.RemoteAddr(), func(_ context.Context, conn net.Conn) (net.Conn, error) {
			return conn, nil
		}, nil)
	}()

	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	}
	auth, err := wire.MakeAuthFrameWithSession("secret", config.EffectiveSpec(), wire.SessionID{0xb1})
	if err != nil {
		t.Fatal(err)
	}
	setup, err := wire.EncodeFlowSetup(header, "example.com:53", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := clientConn.Write(append(auth, setup...))
		writeDone <- writeErr
	}()
	assertTask7UOTFrame(t, clientConn, wire.UOTFrame{Kind: wire.UOTFrameReady})
	var retained net.PacketConn
	select {
	case retained = <-routed:
	case <-time.After(time.Second):
		t.Fatal("ServeTCP did not route the READY packet flow")
	}
	if retained == nil {
		t.Fatal("upstream retained a nil packet connection")
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("ServeTCP = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeTCP did not return after successful handoff")
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("request write = %v", err)
	}
	handler.tasks.mu.Lock()
	activeTasks := len(handler.tasks.tasks)
	handler.tasks.mu.Unlock()
	if activeTasks != 1 {
		t.Fatalf("tasks after handoff = %d, want one transferred route owner", activeTasks)
	}

	cancelParent()
	_ = clientConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	frame, readErr := wire.ReadUOTFrame(clientConn)
	if readErr == nil && frame.Kind == wire.UOTFrameClose {
		t.Fatal("forced parent cancellation emitted typed CLOSE")
	}
	if readErr == nil {
		t.Fatalf("unexpected frame after forced parent cancellation: %+v", frame)
	}
	if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
		t.Fatal("Serve parent cancellation was lost after TCP handoff")
	}
	assertTask7FourthHandlerResources(t, handler)
}

func TestTask7FourthReviewFirstHandlerShutdownHonorsDeadlineWhileCleanupContinues(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{Shutdown: time.Second})
	physical := newTask7FourthBlockingPhysicalClose()
	t.Cleanup(physical.Release)
	_, _, err := handler.tasks.StartTransport(context.Background(), func(error) {
		_ = physical.CloseWithError(0, "shutdown")
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	firstDone := make(chan error, 1)
	go func() { firstDone <- handler.Shutdown(ctx) }()
	waitTask7FourthSignal(t, physical.entered, "Handler cleanup did not enter physical CloseWithError")
	select {
	case err := <-firstDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("first Handler.Shutdown = %v, want deadline", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("first Handler.Shutdown ignored its own deadline")
	}
	select {
	case <-physical.returned:
		t.Fatal("physical CloseWithError returned before test release")
	default:
	}

	physical.Release()
	waitTask7FourthSignal(t, physical.returned, "physical CloseWithError did not finish after release")
	waitTask7FourthSignal(t, handler.shutdown.Done(), "Handler coordinator did not finish after physical close returned")
	if err := handler.Shutdown(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cached Handler shutdown result = %v, want deadline", err)
	}
	if got := physical.calls.Load(); got != 1 {
		t.Fatalf("physical CloseWithError calls = %d, want 1", got)
	}
	assertTask7FourthHandlerResources(t, handler)
}

func TestTask7FourthReviewFirstServerCloseHonorsDeadlineWhileCleanupContinues(t *testing.T) {
	handler, config := newFlowTestHandler(t, noopUpstream{}, Timeouts{Shutdown: 25 * time.Millisecond})
	listener := newTask7FourthBlockingListener()
	t.Cleanup(listener.Release)
	server := &Server{config: config, handler: handler, listener: listener}
	firstDone := make(chan error, 1)
	go func() { firstDone <- server.Close() }()
	waitTask7FourthSignal(t, listener.entered, "Server cleanup did not enter listener Close")
	select {
	case err := <-firstDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("first Server.Close = %v, want deadline", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("first Server.Close ignored its configured deadline")
	}
	select {
	case <-listener.returned:
		t.Fatal("listener Close returned before test release")
	default:
	}

	listener.Release()
	waitTask7FourthSignal(t, listener.returned, "listener Close did not finish after release")
	waitTask7FourthSignal(t, server.shutdown.Done(), "Server coordinator did not finish after listener close returned")
	if err := server.Shutdown(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cached Server shutdown result = %v, want deadline", err)
	}
	if got := listener.calls.Load(); got != 1 {
		t.Fatalf("listener Close calls = %d, want 1", got)
	}
}

func assertTask7FourthHandlerResources(t *testing.T, handler *Handler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.tasks.Wait(ctx); err != nil {
		t.Fatalf("tracked tasks did not finish: %v", err)
	}
	handler.claims.mu.Lock()
	claims := len(handler.claims.entries)
	permits := 0
	for _, count := range handler.claims.udpInUse {
		permits += count
	}
	handler.claims.mu.Unlock()
	if claims != 0 || permits != 0 {
		t.Fatalf("claim resources: claims=%d permits=%d", claims, permits)
	}
	handler.tasks.mu.Lock()
	tasks := len(handler.tasks.tasks)
	handler.tasks.mu.Unlock()
	if tasks != 0 {
		t.Fatalf("tracked tasks = %d", tasks)
	}
}

func waitTask7FourthSignal(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func waitTask7FourthError(t *testing.T, ch <-chan error, message string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		t.Fatal(message)
		return nil
	}
}

type task7FourthAbortContractQuicConn struct {
	closed            chan struct{}
	acceptEntered     chan struct{}
	receiveEntered    chan struct{}
	sendEntered       chan struct{}
	closeReturned     chan struct{}
	sendObservedAbort chan struct{}
	allowSendReturn   chan struct{}
	closeOnce         sync.Once
	acceptOnce        sync.Once
	receiveOnce       sync.Once
	sendOnce          sync.Once
	closeReturnOnce   sync.Once
	sendAbortOnce     sync.Once
	closeCalls        atomic.Int32
}

func newTask7FourthAbortContractQuicConn() *task7FourthAbortContractQuicConn {
	return &task7FourthAbortContractQuicConn{
		closed: make(chan struct{}), acceptEntered: make(chan struct{}), receiveEntered: make(chan struct{}),
		sendEntered: make(chan struct{}), closeReturned: make(chan struct{}), sendObservedAbort: make(chan struct{}),
		allowSendReturn: make(chan struct{}),
	}
}

func (c *task7FourthAbortContractQuicConn) AcceptStream(context.Context) (QuicStream, error) {
	c.acceptOnce.Do(func() { close(c.acceptEntered) })
	<-c.closed
	return nil, net.ErrClosed
}

func (c *task7FourthAbortContractQuicConn) ReceiveDatagram(context.Context) ([]byte, error) {
	c.receiveOnce.Do(func() { close(c.receiveEntered) })
	<-c.closed
	return nil, net.ErrClosed
}

func (c *task7FourthAbortContractQuicConn) SendDatagram([]byte) error {
	c.sendOnce.Do(func() { close(c.sendEntered) })
	<-c.closed
	c.sendAbortOnce.Do(func() { close(c.sendObservedAbort) })
	<-c.allowSendReturn
	return net.ErrClosed
}

func (c *task7FourthAbortContractQuicConn) CloseWithError(uint64, string) error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	c.closeReturnOnce.Do(func() { close(c.closeReturned) })
	return nil
}

func (c *task7FourthAbortContractQuicConn) Close() error {
	return c.CloseWithError(uint64(wire.CloseErrCodeOK), "")
}

func (*task7FourthAbortContractQuicConn) Context() context.Context { return context.Background() }
func (*task7FourthAbortContractQuicConn) LocalAddr() net.Addr      { return &net.UDPAddr{} }
func (*task7FourthAbortContractQuicConn) RemoteAddr() net.Addr     { return &net.UDPAddr{} }

type task7FourthBlockingPhysicalClose struct {
	entered      chan struct{}
	returned     chan struct{}
	release      chan struct{}
	enter        sync.Once
	returnedOnce sync.Once
	releaseOnce  sync.Once
	calls        atomic.Int32
}

func newTask7FourthBlockingPhysicalClose() *task7FourthBlockingPhysicalClose {
	return &task7FourthBlockingPhysicalClose{
		entered: make(chan struct{}), returned: make(chan struct{}), release: make(chan struct{}),
	}
}

func (c *task7FourthBlockingPhysicalClose) CloseWithError(uint64, string) error {
	c.calls.Add(1)
	c.enter.Do(func() { close(c.entered) })
	<-c.release
	c.returnedOnce.Do(func() { close(c.returned) })
	return nil
}

func (c *task7FourthBlockingPhysicalClose) Release() {
	c.releaseOnce.Do(func() { close(c.release) })
}

type task7FourthBlockingListener struct {
	entered      chan struct{}
	returned     chan struct{}
	release      chan struct{}
	enterOnce    sync.Once
	returnedOnce sync.Once
	releaseOnce  sync.Once
	calls        atomic.Int32
}

func newTask7FourthBlockingListener() *task7FourthBlockingListener {
	return &task7FourthBlockingListener{
		entered: make(chan struct{}), returned: make(chan struct{}), release: make(chan struct{}),
	}
}

func (*task7FourthBlockingListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }

func (l *task7FourthBlockingListener) Close() error {
	l.calls.Add(1)
	l.enterOnce.Do(func() { close(l.entered) })
	<-l.release
	l.returnedOnce.Do(func() { close(l.returned) })
	return nil
}

func (*task7FourthBlockingListener) Addr() net.Addr { return &net.TCPAddr{} }

func (l *task7FourthBlockingListener) Release() {
	l.releaseOnce.Do(func() { close(l.release) })
}

var (
	_ QuicConn     = (*task7FourthAbortContractQuicConn)(nil)
	_ net.Listener = (*task7FourthBlockingListener)(nil)
)
