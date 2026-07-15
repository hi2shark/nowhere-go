package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

func TestTask7ReReviewExpiredTokenCannotStealReusedFlowID(t *testing.T) {
	packets := make(chan net.PacketConn, 2)
	handler, config := newFlowTestHandler(t, upstreamFuncs{
		packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
			if err := readiness.Ready(); err != nil {
				return err
			}
			packets <- pc
			return nil
		},
	}, Timeouts{RequestIdle: time.Minute, UDPIdle: time.Minute})
	clock := &task7FakeClock{now: time.Unix(100, 0)}
	handler.now = clock.Now
	session := newPortalSession(wire.SessionID{0x91}, &task7PMTUQuicConn{}, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)

	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}
	setup, err := wire.EncodeFlowSetup(header, "example.com:53", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}

	controlA := newTask7FINStream(setup)
	doneA := make(chan struct{})
	go func() {
		session.handleStream(context.Background(), controlA)
		close(doneA)
	}()
	waitTask7ReReviewSignal(t, controlA.finWaitStarted, "control A did not reach FIN wait")

	session.mu.Lock()
	tokenA := session.pendingControls[header.FlowID]
	session.mu.Unlock()
	if tokenA == nil {
		t.Fatal("control A did not install a preactivation token")
	}
	clock.Advance(preactivationTTL)
	session.expirePendingControls(clock.Now())

	controlB := newTask7FINStream(setup)
	doneB := make(chan struct{})
	go func() {
		session.handleStream(context.Background(), controlB)
		close(doneB)
	}()
	waitTask7ReReviewSignal(t, controlB.finWaitStarted, "control B did not reach FIN wait")

	session.mu.Lock()
	tokenB := session.pendingControls[header.FlowID]
	session.mu.Unlock()
	if tokenB == nil || tokenB == tokenA {
		t.Fatal("control B did not replace the expired token")
	}
	frames, err := wire.EncodeUDPDataFragments(header.FlowID, 2, []byte("new"), 1200)
	if err != nil {
		t.Fatal(err)
	}
	session.handleDatagram(context.Background(), frames[0])

	close(controlA.fin)
	waitTask7ReReviewSignal(t, doneA, "stale control A did not finish")
	select {
	case pc := <-packets:
		_ = pc.Close()
		close(controlB.fin)
		t.Fatal("stale control A dispatched an upstream flow")
	default:
	}

	session.mu.Lock()
	flow := session.flows[header.FlowID]
	current := session.pendingControls[header.FlowID]
	pendingFrames := session.pendingFrames
	pendingBytes := session.pendingBytes
	session.mu.Unlock()
	if flow != nil {
		t.Fatal("stale control A inserted a flow")
	}
	if current != tokenB || pendingFrames != 1 || pendingBytes != len(frames[0]) {
		t.Fatalf("stale activation changed control B: token=%p want=%p frames=%d bytes=%d", current, tokenB, pendingFrames, pendingBytes)
	}

	close(controlB.fin)
	var pc net.PacketConn
	select {
	case pc = <-packets:
	case <-time.After(time.Second):
		t.Fatal("control B did not dispatch after FIN")
	}
	defer pc.Close()
	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 16)
	n, _, err := pc.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "new" {
		t.Fatalf("control B packet = %q, want new", got)
	}
	waitTask7ReReviewSignal(t, doneB, "control B did not finish")
}

func TestTask7ReReviewBlockedQUICSendIsAbortedByClose(t *testing.T) {
	packets := make(chan net.PacketConn, 1)
	handler, _ := newFlowTestHandler(t, upstreamFuncs{
		packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
			if err := readiness.Ready(); err != nil {
				return err
			}
			packets <- pc
			return nil
		},
	}, Timeouts{UDPIdle: time.Minute})
	conn := newTask7ReReviewBlockingSendQuicConn()
	session := newPortalSession(wire.SessionID{0x92}, conn, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)

	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}
	pending, err := session.beginPendingUDPControl(header)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.handleUDPControl(context.Background(), newTask7MemoryConn(nil), &net.UDPAddr{}, header, "example.com:53", pending); err != nil {
		t.Fatal(err)
	}

	var pc net.PacketConn
	select {
	case pc = <-packets:
	case <-time.After(time.Second):
		t.Fatal("QUIC flow was not routed")
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := pc.WriteTo([]byte("blocked"), nil)
		writeDone <- err
	}()
	waitTask7ReReviewSignal(t, conn.sendEntered, "SendDatagram did not block")

	closeDone := make(chan error, 1)
	go func() { closeDone <- pc.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close = %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Close did not abort the physical QUIC session to unblock SendDatagram")
	}
	select {
	case err := <-writeDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked WriteTo = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked WriteTo did not return after Close")
	}
	if conn.closeCalls.Load() == 0 {
		t.Fatal("Close did not close the physical QUIC session")
	}
}

func TestTask7ReReviewShutdownDeadlineUsesForcedTermination(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{FlowPair: time.Minute, UDPIdle: time.Minute})
	downlinkConn := newTask7MemoryConn(nil)
	pc := newPairedUDPConn(&pairedUDP{
		FlowID: 1, Target: "example.com:53", Uplink: task7EmptyUplink{},
		Downlink: newTCPUDPDownlink(downlinkConn), IdleTimeout: time.Minute,
	}).(*pairedUDPConn)
	pc.markReady()
	taskCtx, finish, err := handler.tasks.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	flowDone := make(chan struct{})
	go func() {
		<-taskCtx.Done()
		pc.closeWithError(context.Cause(taskCtx))
		finish()
		close(flowDone)
	}()

	writer := newTask7ReReviewBlockingWriteConn(flowDone)
	claim := task6Claim(
		wire.SessionID{0x93}, 2, 0, wire.FlowRoleAttach, wire.CarrierTCP,
		task6Metadata(wire.FlowKindTCP, wire.CarrierUDP, wire.CarrierTCP),
	)
	claim.Stream = writer
	submitDone := make(chan error, 1)
	go func() {
		_, err := handler.claims.Submit(context.Background(), claim)
		submitDone <- err
	}()
	waitTask6Entries(t, handler.claims, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- handler.Shutdown(ctx) }()
	waitTask7ReReviewSignal(t, writer.writeEntered, "shutdown did not block in selected rejection")
	select {
	case err := <-shutdownDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Shutdown = %v, want context deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Shutdown did not return at the caller deadline")
	}
	waitTask7ReReviewSignal(t, flowDone, "forced flow cleanup did not finish")
	if got := downlinkConn.Bytes(); len(got) != 0 {
		t.Fatalf("forced shutdown wrote typed CLOSE after deadline: %x", got)
	}
	select {
	case err := <-submitDone:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("pending Submit = %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending Submit did not finish")
	}

	ordinaryConn := newTask7MemoryConn(nil)
	ordinary := newPairedUDPConn(&pairedUDP{
		FlowID: 3, Target: "example.com:53", Uplink: task7EmptyUplink{},
		Downlink: newTCPUDPDownlink(ordinaryConn), IdleTimeout: time.Minute,
	}).(*pairedUDPConn)
	ordinary.markReady()
	ordinary.closeWithError(context.DeadlineExceeded)
	assertTask7UOTFrame(t, bytes.NewReader(ordinaryConn.Bytes()), wire.UOTFrame{Kind: wire.UOTFrameClose})
}

func TestTask7ReReviewServeAfterShutdownClosesListenerWithoutAccept(t *testing.T) {
	handler, config := newFlowTestHandler(t, noopUpstream{}, Timeouts{Shutdown: time.Second})
	server := &Server{config: config, handler: handler}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	listener := &task7ReReviewCountingListener{}
	if err := server.Serve(context.Background(), listener); err != nil {
		t.Fatalf("Serve after shutdown = %v", err)
	}
	if got := listener.acceptCalls.Load(); got != 0 {
		t.Fatalf("Accept calls after shutdown = %d, want 0", got)
	}
	if got := listener.closeCalls.Load(); got != 1 {
		t.Fatalf("listener Close calls after shutdown = %d, want 1", got)
	}
}

func TestTask7ReReviewConcurrentServeAndShutdownClosesListener(t *testing.T) {
	handler, config := newFlowTestHandler(t, noopUpstream{}, Timeouts{Shutdown: time.Second})
	server := &Server{config: config, handler: handler}
	listener := newTask7ReReviewBlockingListener()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background(), listener) }()
	waitTask7ReReviewSignal(t, listener.acceptEntered, "Serve did not enter Accept")

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		shutdownDone <- server.Shutdown(ctx)
	}()
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Shutdown did not finish")
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop after Shutdown")
	}
	if got := listener.closeCalls.Load(); got != 1 {
		t.Fatalf("listener Close calls = %d, want 1", got)
	}
}

func waitTask7ReReviewSignal(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

type task7ReReviewBlockingSendQuicConn struct {
	sendEntered chan struct{}
	closed      chan struct{}
	sendOnce    sync.Once
	closeOnce   sync.Once
	closeCalls  atomic.Int32
}

func newTask7ReReviewBlockingSendQuicConn() *task7ReReviewBlockingSendQuicConn {
	return &task7ReReviewBlockingSendQuicConn{sendEntered: make(chan struct{}), closed: make(chan struct{})}
}

func (c *task7ReReviewBlockingSendQuicConn) AcceptStream(ctx context.Context) (QuicStream, error) {
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (c *task7ReReviewBlockingSendQuicConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (c *task7ReReviewBlockingSendQuicConn) SendDatagram([]byte) error {
	c.sendOnce.Do(func() { close(c.sendEntered) })
	<-c.closed
	return net.ErrClosed
}
func (c *task7ReReviewBlockingSendQuicConn) CloseWithError(uint64, string) error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *task7ReReviewBlockingSendQuicConn) Close() error {
	return c.CloseWithError(uint64(wire.CloseErrCodeOK), "")
}
func (*task7ReReviewBlockingSendQuicConn) Context() context.Context { return context.Background() }
func (*task7ReReviewBlockingSendQuicConn) LocalAddr() net.Addr      { return &net.UDPAddr{} }
func (*task7ReReviewBlockingSendQuicConn) RemoteAddr() net.Addr     { return &net.UDPAddr{} }

type task7ReReviewBlockingWriteConn struct {
	writeEntered chan struct{}
	closed       chan struct{}
	flowDone     <-chan struct{}
	writeOnce    sync.Once
	closeOnce    sync.Once
}

func newTask7ReReviewBlockingWriteConn(flowDone <-chan struct{}) *task7ReReviewBlockingWriteConn {
	return &task7ReReviewBlockingWriteConn{
		writeEntered: make(chan struct{}), closed: make(chan struct{}), flowDone: flowDone,
	}
}
func (c *task7ReReviewBlockingWriteConn) Read([]byte) (int, error) {
	<-c.closed
	<-c.flowDone
	return 0, net.ErrClosed
}
func (c *task7ReReviewBlockingWriteConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeEntered) })
	<-c.closed
	<-c.flowDone
	return 0, net.ErrClosed
}
func (c *task7ReReviewBlockingWriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	<-c.flowDone
	return nil
}
func (*task7ReReviewBlockingWriteConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*task7ReReviewBlockingWriteConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*task7ReReviewBlockingWriteConn) SetDeadline(time.Time) error      { return nil }
func (*task7ReReviewBlockingWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*task7ReReviewBlockingWriteConn) SetWriteDeadline(time.Time) error { return nil }

type task7ReReviewCountingListener struct {
	acceptCalls atomic.Int32
	closeCalls  atomic.Int32
}

func (l *task7ReReviewCountingListener) Accept() (net.Conn, error) {
	l.acceptCalls.Add(1)
	return nil, net.ErrClosed
}
func (l *task7ReReviewCountingListener) Close() error {
	l.closeCalls.Add(1)
	return nil
}
func (*task7ReReviewCountingListener) Addr() net.Addr { return &net.TCPAddr{} }

type task7ReReviewBlockingListener struct {
	acceptEntered chan struct{}
	closed        chan struct{}
	acceptOnce    sync.Once
	closeOnce     sync.Once
	closeCalls    atomic.Int32
}

func newTask7ReReviewBlockingListener() *task7ReReviewBlockingListener {
	return &task7ReReviewBlockingListener{acceptEntered: make(chan struct{}), closed: make(chan struct{})}
}
func (l *task7ReReviewBlockingListener) Accept() (net.Conn, error) {
	l.acceptOnce.Do(func() { close(l.acceptEntered) })
	<-l.closed
	return nil, net.ErrClosed
}
func (l *task7ReReviewBlockingListener) Close() error {
	l.closeCalls.Add(1)
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}
func (*task7ReReviewBlockingListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestTask7ReReviewPreactivationHasPerControlBounds(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{UDPIdle: time.Minute})
	clock := &task7FakeClock{now: time.Unix(200, 0)}
	handler.now = clock.Now
	session := newPortalSession(wire.SessionID{0x94}, &task7PMTUQuicConn{}, handler, &net.UDPAddr{})
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}

	header.FlowID = 1
	first, err := session.beginPendingUDPControl(header)
	if err != nil {
		t.Fatal(err)
	}
	small := wire.UDPFrame{
		Type: wire.UDPFrameData, FlowID: 1,
		Fragment: wire.UDPFragment{PacketID: 1, FragmentCount: 1, TotalLen: 1, Payload: []byte{1}},
	}
	for i := 0; i < preactivationFramesPerControl*2; i++ {
		small.Fragment.PacketID = uint32(i + 1)
		if !session.bufferPendingUDPData(small, 1) {
			t.Fatal("known first control was not recognized")
		}
	}
	if got := len(first.frames); got != preactivationFramesPerControl {
		t.Fatalf("first control frames = %d, want %d", got, preactivationFramesPerControl)
	}

	header.FlowID = 2
	second, err := session.beginPendingUDPControl(header)
	if err != nil {
		t.Fatal(err)
	}
	small.FlowID = 2
	if !session.bufferPendingUDPData(small, 1) || len(second.frames) != 1 {
		t.Fatal("first control monopolized the connection-wide frame budget")
	}

	header.FlowID = 3
	third, err := session.beginPendingUDPControl(header)
	if err != nil {
		t.Fatal(err)
	}
	largeSize := preactivationBytesPerControl/2 + 1
	large := wire.UDPFrame{
		Type: wire.UDPFrameData, FlowID: 3,
		Fragment: wire.UDPFragment{
			PacketID: 1, FragmentCount: 1, TotalLen: uint16(largeSize), Payload: make([]byte, largeSize),
		},
	}
	if !session.bufferPendingUDPData(large, largeSize) {
		t.Fatal("known byte-bound control was not recognized")
	}
	large.Fragment.PacketID++
	if !session.bufferPendingUDPData(large, largeSize) {
		t.Fatal("known byte-bound control was not recognized on overflow")
	}
	if len(third.frames) != 1 || third.bytes != largeSize {
		t.Fatalf("third control retained frames=%d bytes=%d, want 1/%d", len(third.frames), third.bytes, largeSize)
	}

	session.mu.Lock()
	globalFrames, globalBytes := session.pendingFrames, session.pendingBytes
	session.mu.Unlock()
	if globalFrames != preactivationFramesPerControl+2 || globalBytes > preactivationByteLimit {
		t.Fatalf("global preactivation accounting frames=%d bytes=%d", globalFrames, globalBytes)
	}
	clock.Advance(preactivationTTL)
	session.expirePendingControls(clock.Now())
	session.mu.Lock()
	pending, frames, bytesUsed := len(session.pendingControls), session.pendingFrames, session.pendingBytes
	session.mu.Unlock()
	if pending != 0 || frames != 0 || bytesUsed != 0 {
		t.Fatalf("expiry retained pending=%d frames=%d bytes=%d", pending, frames, bytesUsed)
	}

	header.FlowID = 4
	if _, err := session.beginPendingUDPControl(header); err != nil {
		t.Fatal(err)
	}
	small.FlowID = 4
	if !session.bufferPendingUDPData(small, 1) {
		t.Fatal("known final control was not recognized")
	}
	session.Close()
	session.mu.Lock()
	pending, frames, bytesUsed = len(session.pendingControls), session.pendingFrames, session.pendingBytes
	session.mu.Unlock()
	if pending != 0 || frames != 0 || bytesUsed != 0 {
		t.Fatalf("session close retained pending=%d frames=%d bytes=%d", pending, frames, bytesUsed)
	}
}

func TestTask7ReReviewConcurrentHandlerShutdownWaitsForCleanup(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{FlowPair: time.Minute})
	writer := newTask7ReReviewReleaseWriteConn()
	claim := task6Claim(
		wire.SessionID{0x95}, 1, 0, wire.FlowRoleAttach, wire.CarrierTCP,
		task6Metadata(wire.FlowKindTCP, wire.CarrierUDP, wire.CarrierTCP),
	)
	claim.Stream = writer
	submitDone := make(chan error, 1)
	go func() {
		_, err := handler.claims.Submit(context.Background(), claim)
		submitDone <- err
	}()
	waitTask6Entries(t, handler.claims, 1)

	firstDone := make(chan error, 1)
	go func() { firstDone <- handler.Shutdown(context.Background()) }()
	waitTask7ReReviewSignal(t, writer.writeEntered, "first Shutdown did not enter claim cleanup")
	secondDone := make(chan error, 1)
	secondStarted := make(chan struct{})
	go func() {
		close(secondStarted)
		secondDone <- handler.Shutdown(context.Background())
	}()
	<-secondStarted
	select {
	case err := <-secondDone:
		t.Fatalf("second Shutdown returned before cleanup completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(writer.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Shutdown = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second Shutdown = %v", err)
	}
	select {
	case err := <-submitDone:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("pending Submit = %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending Submit did not finish")
	}
}

func TestTask7ReReviewConcurrentServerShutdownAndCloseWaitForCleanup(t *testing.T) {
	handler, config := newFlowTestHandler(t, noopUpstream{}, Timeouts{Shutdown: time.Second})
	listener := newTask7ReReviewBlockingCloseListener()
	server := &Server{config: config, handler: handler, listener: listener}
	firstDone := make(chan error, 1)
	go func() { firstDone <- server.Shutdown(context.Background()) }()
	waitTask7ReReviewSignal(t, listener.closeEntered, "first Shutdown did not enter listener Close")
	secondDone := make(chan error, 1)
	go func() { secondDone <- server.Close() }()
	select {
	case err := <-secondDone:
		t.Fatalf("concurrent Close returned before listener cleanup completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(listener.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("Close = %v", err)
	}
	if got := listener.closeCalls.Load(); got != 1 {
		t.Fatalf("listener Close calls = %d, want 1", got)
	}
}

func TestTask7ReReviewConcurrentSessionCloseWaitsForCleanup(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{})
	conn := newTask7ReReviewBlockingCloseQuicConn()
	session := newPortalSession(wire.SessionID{0x96}, conn, handler, &net.UDPAddr{})
	firstDone := make(chan struct{})
	go func() {
		session.Close()
		close(firstDone)
	}()
	waitTask7ReReviewSignal(t, conn.closeEntered, "first session Close did not enter physical close")
	secondDone := make(chan struct{})
	go func() {
		session.Close()
		close(secondDone)
	}()
	select {
	case <-secondDone:
		t.Fatal("second session Close returned before physical cleanup completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(conn.release)
	waitTask7ReReviewSignal(t, firstDone, "first session Close did not finish")
	waitTask7ReReviewSignal(t, secondDone, "second session Close did not finish")
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("physical close calls = %d, want 1", got)
	}
}

func TestTask7ReReviewServeQUICStartsAndStopsExpiryDriver(t *testing.T) {
	handler, config := newFlowTestHandler(t, noopUpstream{}, Timeouts{Auth: time.Minute, UDPIdle: time.Minute})
	clock := &task7FakeClock{now: time.Now()}
	ticker := &task7ReviewTicker{ticks: make(chan time.Time, 1)}
	tickerCreated := make(chan struct{})
	handler.now = clock.Now
	handler.newReassemblyTicker = func(time.Duration) reassemblyTicker {
		close(tickerCreated)
		return ticker
	}
	sessionID := wire.SessionID{0x97}
	auth, err := wire.MakeAuthFrameWithSession("secret", config.EffectiveSpec(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	conn := &fakeQuicConn{stream: newRecordingQuicStream(auth)}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- handler.ServeQUIC(ctx, conn) }()
	waitTask7ReReviewSignal(t, tickerCreated, "ServeQUIC did not start the expiry driver")
	session := handler.sessions.Current(sessionID)
	if session == nil {
		t.Fatal("ServeQUIC did not register the authenticated session")
	}
	flow := newNowuFlow(session, 1, "example.com:53")
	if err := session.insertNOWUFlow(flow); err != nil {
		t.Fatal(err)
	}
	flow.deliverFragment(testUDPFragment(1, 0, 2, 4, "ab"))
	assertTask7Budget(t, session.budget, 2)
	clock.Advance(nowuPartialTTL)
	ticker.ticks <- clock.Now()
	waitTask7ReReviewCondition(t, func() bool {
		session.reassembler.mu.Lock()
		defer session.reassembler.mu.Unlock()
		return len(session.reassembler.slots) == 0
	}, "ServeQUIC expiry driver did not expire reassembly")
	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("ServeQUIC = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeQUIC did not stop after cancellation")
	}
	if !ticker.stopped.Load() {
		t.Fatal("ServeQUIC session close did not stop the expiry driver")
	}
}

func TestTask7ReReviewServeQUICBuffersIndependentDatagramUntilControlFIN(t *testing.T) {
	packets := make(chan net.PacketConn, 1)
	handler, config := newFlowTestHandler(t, upstreamFuncs{
		packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
			if err := readiness.Ready(); err != nil {
				return err
			}
			packets <- pc
			return nil
		},
	}, Timeouts{Auth: time.Minute, RequestIdle: time.Minute, UDPIdle: time.Minute})
	sessionID := wire.SessionID{0x98}
	auth, err := wire.MakeAuthFrameWithSession("secret", config.EffectiveSpec(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}
	setup, err := wire.EncodeFlowSetup(header, "example.com:53", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	frames, err := wire.EncodeUDPDataFragments(header.FlowID, 1, []byte("early"), 1200)
	if err != nil {
		t.Fatal(err)
	}
	control := newTask7FINStream(setup)
	conn := newTask7ReReviewOrderedQuicConn(newRecordingQuicStream(auth), control, frames[0])
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- handler.ServeQUIC(ctx, conn) }()
	waitTask7ReReviewSignal(t, control.finWaitStarted, "control did not reach FIN wait through ServeQUIC")
	close(conn.datagramRelease)
	waitTask7ReReviewSignal(t, conn.datagramDelivered, "ReceiveDatagram did not deliver independent DATA")
	select {
	case pc := <-packets:
		_ = pc.Close()
		t.Fatal("ServeQUIC dispatched before control FIN")
	default:
	}
	close(control.fin)
	var pc net.PacketConn
	select {
	case pc = <-packets:
	case <-time.After(time.Second):
		t.Fatal("ServeQUIC did not dispatch after control FIN")
	}
	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 16)
	n, _, err := pc.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "early" {
		t.Fatalf("buffered packet = %q, want early", got)
	}
	_ = pc.Close()
	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("ServeQUIC = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeQUIC did not stop after cancellation")
	}
}

func waitTask7ReReviewCondition(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal(message)
		}
	}
}

type task7ReReviewReleaseWriteConn struct {
	writeEntered chan struct{}
	release      chan struct{}
	writeOnce    sync.Once
}

func newTask7ReReviewReleaseWriteConn() *task7ReReviewReleaseWriteConn {
	return &task7ReReviewReleaseWriteConn{writeEntered: make(chan struct{}), release: make(chan struct{})}
}
func (*task7ReReviewReleaseWriteConn) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (c *task7ReReviewReleaseWriteConn) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeEntered) })
	<-c.release
	return len(p), nil
}
func (*task7ReReviewReleaseWriteConn) Close() error                     { return nil }
func (*task7ReReviewReleaseWriteConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*task7ReReviewReleaseWriteConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*task7ReReviewReleaseWriteConn) SetDeadline(time.Time) error      { return nil }
func (*task7ReReviewReleaseWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*task7ReReviewReleaseWriteConn) SetWriteDeadline(time.Time) error { return nil }

type task7ReReviewBlockingCloseListener struct {
	closeEntered chan struct{}
	release      chan struct{}
	closeOnce    sync.Once
	closeCalls   atomic.Int32
}

func newTask7ReReviewBlockingCloseListener() *task7ReReviewBlockingCloseListener {
	return &task7ReReviewBlockingCloseListener{closeEntered: make(chan struct{}), release: make(chan struct{})}
}
func (*task7ReReviewBlockingCloseListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *task7ReReviewBlockingCloseListener) Close() error {
	l.closeOnce.Do(func() {
		l.closeCalls.Add(1)
		close(l.closeEntered)
		<-l.release
	})
	return nil
}
func (*task7ReReviewBlockingCloseListener) Addr() net.Addr { return &net.TCPAddr{} }

type task7ReReviewBlockingCloseQuicConn struct {
	closeEntered chan struct{}
	release      chan struct{}
	closeOnce    sync.Once
	closeCalls   atomic.Int32
}

func newTask7ReReviewBlockingCloseQuicConn() *task7ReReviewBlockingCloseQuicConn {
	return &task7ReReviewBlockingCloseQuicConn{closeEntered: make(chan struct{}), release: make(chan struct{})}
}
func (*task7ReReviewBlockingCloseQuicConn) AcceptStream(ctx context.Context) (QuicStream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*task7ReReviewBlockingCloseQuicConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*task7ReReviewBlockingCloseQuicConn) SendDatagram([]byte) error { return nil }
func (c *task7ReReviewBlockingCloseQuicConn) CloseWithError(uint64, string) error {
	c.closeOnce.Do(func() {
		c.closeCalls.Add(1)
		close(c.closeEntered)
		<-c.release
	})
	return nil
}
func (c *task7ReReviewBlockingCloseQuicConn) Close() error {
	return c.CloseWithError(uint64(wire.CloseErrCodeOK), "")
}
func (*task7ReReviewBlockingCloseQuicConn) Context() context.Context { return context.Background() }
func (*task7ReReviewBlockingCloseQuicConn) LocalAddr() net.Addr      { return &net.UDPAddr{} }
func (*task7ReReviewBlockingCloseQuicConn) RemoteAddr() net.Addr     { return &net.UDPAddr{} }

type task7ReReviewOrderedQuicConn struct {
	mu                sync.Mutex
	streams           []QuicStream
	datagram          []byte
	datagramRelease   chan struct{}
	datagramDelivered chan struct{}
	datagramSent      bool
	closed            chan struct{}
	closeOnce         sync.Once
}

func newTask7ReReviewOrderedQuicConn(auth, control QuicStream, datagram []byte) *task7ReReviewOrderedQuicConn {
	return &task7ReReviewOrderedQuicConn{
		streams: []QuicStream{auth, control}, datagram: append([]byte(nil), datagram...),
		datagramRelease: make(chan struct{}), datagramDelivered: make(chan struct{}), closed: make(chan struct{}),
	}
}
func (c *task7ReReviewOrderedQuicConn) AcceptStream(ctx context.Context) (QuicStream, error) {
	c.mu.Lock()
	if len(c.streams) > 0 {
		stream := c.streams[0]
		c.streams = c.streams[1:]
		c.mu.Unlock()
		return stream, nil
	}
	c.mu.Unlock()
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (c *task7ReReviewOrderedQuicConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-c.datagramRelease:
	case <-c.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	c.mu.Lock()
	if !c.datagramSent {
		c.datagramSent = true
		data := append([]byte(nil), c.datagram...)
		close(c.datagramDelivered)
		c.mu.Unlock()
		return data, nil
	}
	c.mu.Unlock()
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*task7ReReviewOrderedQuicConn) SendDatagram([]byte) error { return nil }
func (c *task7ReReviewOrderedQuicConn) CloseWithError(uint64, string) error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *task7ReReviewOrderedQuicConn) Close() error {
	return c.CloseWithError(uint64(wire.CloseErrCodeOK), "")
}
func (*task7ReReviewOrderedQuicConn) Context() context.Context { return context.Background() }
func (*task7ReReviewOrderedQuicConn) LocalAddr() net.Addr      { return &net.UDPAddr{} }
func (*task7ReReviewOrderedQuicConn) RemoteAddr() net.Addr     { return &net.UDPAddr{} }

var (
	_ QuicConn     = (*task7ReReviewBlockingSendQuicConn)(nil)
	_ QuicConn     = (*task7ReReviewBlockingCloseQuicConn)(nil)
	_ QuicConn     = (*task7ReReviewOrderedQuicConn)(nil)
	_ net.Conn     = (*task7ReReviewBlockingWriteConn)(nil)
	_ net.Conn     = (*task7ReReviewReleaseWriteConn)(nil)
	_ net.Listener = (*task7ReReviewCountingListener)(nil)
	_ net.Listener = (*task7ReReviewBlockingListener)(nil)
	_ net.Listener = (*task7ReReviewBlockingCloseListener)(nil)
)
