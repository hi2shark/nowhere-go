package server

import (
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

func TestTask7ThirdReviewBlockedGracefulNOWUCloseTimesOutAndJoins(t *testing.T) {
	sender := newTask7ThirdBlockingCloseSender()
	t.Cleanup(sender.Abort)
	control := &task7ThirdCountingControl{}
	bound := &quicUDPDownlinkBound{
		flowID: 1,
		base: newQUICUDPDownlink(control, sender.Send, func() int { return 1200 }, func(error) {
			sender.Abort()
		}),
	}

	done := make(chan error, 1)
	go func() { done <- bound.WriteClose() }()
	waitTask7ThirdSignal(t, sender.entered, "typed CLOSE did not enter SendDatagram")
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("WriteClose = %v, want net.ErrClosed", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked typed CLOSE was not timed out and physically aborted")
	}
	waitTask7ThirdSignal(t, sender.exited, "WriteClose returned before the send goroutine exited")
	if got := sender.abortCalls.Load(); got != 1 {
		t.Fatalf("physical abort calls = %d, want 1", got)
	}
	if got := control.closeCalls.Load(); got != 1 {
		t.Fatalf("control Close calls = %d, want 1", got)
	}
}

func TestTask7ThirdReviewForcedCallerUpgradesBlockedGracefulNOWUClose(t *testing.T) {
	sender := newTask7ThirdBlockingCloseSender()
	t.Cleanup(sender.Abort)
	control := &task7ThirdCountingControl{}
	bound := &quicUDPDownlinkBound{
		flowID: 2,
		base: newQUICUDPDownlink(control, sender.Send, func() int { return 1200 }, func(error) {
			sender.Abort()
		}),
	}

	gracefulDone := make(chan error, 1)
	go func() { gracefulDone <- bound.WriteClose() }()
	waitTask7ThirdSignal(t, sender.entered, "typed CLOSE did not enter SendDatagram")
	forcedDone := make(chan error, 1)
	go func() { forcedDone <- bound.Close() }()
	select {
	case err := <-forcedDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("forced Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("forced terminal caller did not upgrade and abort blocked graceful CLOSE")
	}
	select {
	case err := <-gracefulDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("graceful WriteClose = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("graceful terminal caller did not join after forced upgrade")
	}
	waitTask7ThirdSignal(t, sender.exited, "terminal callers returned before the send goroutine exited")
	if got := sender.abortCalls.Load(); got != 1 {
		t.Fatalf("physical abort calls = %d, want 1", got)
	}
	if got := control.closeCalls.Load(); got != 1 {
		t.Fatalf("control Close calls = %d, want 1", got)
	}
	if err := bound.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("cached terminal result = %v, want net.ErrClosed", err)
	}
	if got := control.closeCalls.Load(); got != 1 {
		t.Fatalf("later terminal caller repeated base.Close: calls=%d", got)
	}
}

func TestTask7ThirdReviewPairedForcedCallerUpgradesBlockedGracefulNOWUClose(t *testing.T) {
	sender := newTask7ThirdBlockingCloseSender()
	t.Cleanup(sender.Abort)
	control := &task7ThirdCountingControl{}
	pc := newPairedUDPConn(&pairedUDP{
		FlowID: 3, Target: "example.com:53", Uplink: task7EmptyUplink{},
		Downlink: newQUICUDPDownlink(control, sender.Send, func() int { return 1200 }, func(error) {
			sender.Abort()
		}),
		IdleTimeout: time.Minute,
	}).(*pairedUDPConn)
	pc.markReady()

	gracefulDone := make(chan error, 1)
	go func() { gracefulDone <- pc.Close() }()
	waitTask7ThirdSignal(t, sender.entered, "paired typed CLOSE did not enter SendDatagram")
	forcedDone := make(chan struct{})
	go func() {
		pc.closeWithError(markForcedTermination(ErrClosed))
		close(forcedDone)
	}()
	select {
	case <-forcedDone:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("paired forced caller did not upgrade blocked graceful CLOSE")
	}
	select {
	case err := <-gracefulDone:
		if err != nil {
			t.Fatalf("paired Close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("paired graceful caller did not join after forced upgrade")
	}
	waitTask7ThirdSignal(t, sender.exited, "paired callers returned before the send goroutine exited")
	if got := sender.abortCalls.Load(); got != 1 {
		t.Fatalf("paired physical abort calls = %d, want 1", got)
	}
	if got := control.closeCalls.Load(); got != 1 {
		t.Fatalf("paired control Close calls = %d, want 1", got)
	}
}

func TestTask7ThirdReviewServeQUICPhysicalAbortCleansMultipleFlows(t *testing.T) {
	type routedFlow struct {
		id  uint64
		pc  net.PacketConn
		err error
	}
	routed := make(chan routedFlow, 2)
	handler, config := newFlowTestHandler(t, upstreamFuncs{
		packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
			if err := readiness.Ready(); err != nil {
				return err
			}
			tracked, ok := pc.(*trackedFlowPacketConn)
			if !ok {
				err := errors.New("upstream packet conn is not tracked")
				routed <- routedFlow{err: err}
				return err
			}
			paired, ok := tracked.PacketConn.(*pairedUDPConn)
			if !ok {
				err := errors.New("tracked packet conn is not paired UDP")
				routed <- routedFlow{err: err}
				return err
			}
			routed <- routedFlow{id: paired.flowID, pc: pc}
			return nil
		},
	}, Timeouts{Auth: time.Minute, RequestIdle: time.Minute, UDPIdle: time.Minute, Shutdown: time.Second})

	sessionID := wire.SessionID{0xa3}
	auth, err := wire.MakeAuthFrameWithSession("secret", config.EffectiveSpec(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	streams := []QuicStream{newRecordingQuicStream(auth)}
	for _, flowID := range []uint64{1, 2} {
		header := wire.FlowHeader{
			Role: wire.FlowRoleDuplex, FlowID: flowID, Kind: wire.FlowKindUDP,
			Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
		}
		setup, encodeErr := wire.EncodeFlowSetup(header, "example.com:53", config.EffectiveSpec())
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		streams = append(streams, newRecordingQuicStream(setup))
	}
	conn := newTask7ThirdMultiFlowQuicConn(streams...)
	serveDone := make(chan error, 1)
	go func() { serveDone <- handler.ServeQUIC(context.Background(), conn) }()

	packetConns := make(map[uint64]net.PacketConn, 2)
	for len(packetConns) < 2 {
		select {
		case result := <-routed:
			if result.err != nil {
				t.Fatal(result.err)
			}
			packetConns[result.id] = result.pc
		case <-time.After(time.Second):
			t.Fatal("ServeQUIC did not route both UDP/UDP flows")
		}
	}
	session := handler.sessions.Current(sessionID)
	if session == nil {
		t.Fatal("ServeQUIC session was not registered")
	}
	fragments, err := wire.EncodeUDPDataFragments(2, 1, []byte("partial"), nowuDataHeaderLen+2)
	if err != nil {
		t.Fatal(err)
	}
	if len(fragments) < 2 {
		t.Fatalf("fragment count = %d, want at least 2", len(fragments))
	}
	conn.OfferDatagram(fragments[0])
	waitTask7ThirdCondition(t, func() bool {
		session.reassembler.budget.mu.Lock()
		defer session.reassembler.budget.mu.Unlock()
		return session.reassembler.budget.used > 0
	}, "partial flow did not consume reassembly budget")

	closeDone := make(chan error, 1)
	go func() { closeDone <- packetConns[1].Close() }()
	waitTask7ThirdSignal(t, conn.closeSendEntered, "graceful CLOSE did not block in native SendDatagram")
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("flow Close = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked graceful CLOSE did not physically abort the QUIC session")
	}
	waitTask7ThirdSignal(t, conn.closeSendExited, "flow Close returned before native SendDatagram exited")
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("ServeQUIC = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeQUIC did not finish physical-abort session cleanup")
	}
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("physical QUIC close calls = %d, want 1", got)
	}
	assertTask7SessionResources(t, handler, session)
}

func TestTask7ThirdReviewServeParentCancelIsForcedAndPreservesValues(t *testing.T) {
	type contextKey struct{}
	const contextValue = "preserved"
	upstreamStarted := make(chan struct{})
	upstreamDone := make(chan struct{})
	upstream := upstreamFuncs{
		packet: func(ctx context.Context, _ net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
			if got := ctx.Value(contextKey{}); got != contextValue {
				return errors.New("parent context value was not preserved")
			}
			if err := readiness.Ready(); err != nil {
				return err
			}
			close(upstreamStarted)
			<-ctx.Done()
			close(upstreamDone)
			return context.Cause(ctx)
		},
	}
	config, err := NewConfig(ConfigOptions{
		Password: "secret", Networks: []Network{NetworkTCP},
		Timeouts: Timeouts{Auth: time.Minute, RequestIdle: time.Minute, UDPIdle: time.Minute, Shutdown: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerOptions{
		Config: config, Upstream: upstream,
		TLSHandshake: func(_ context.Context, conn net.Conn) (net.Conn, error) { return conn, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	listener := newTask7ThirdSingleConnListener()
	parent, cancelParent := context.WithCancel(context.WithValue(context.Background(), contextKey{}, contextValue))
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(parent, listener) }()

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	listener.Offer(serverConn)
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	}
	auth, err := wire.MakeAuthFrameWithSession("secret", config.EffectiveSpec(), wire.SessionID{0xa1})
	if err != nil {
		t.Fatal(err)
	}
	setup, err := wire.EncodeFlowSetup(header, "example.com:53", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(append(auth, setup...))
		writeDone <- err
	}()
	assertTask7UOTFrame(t, clientConn, wire.UOTFrame{Kind: wire.UOTFrameReady})
	waitTask7ThirdSignal(t, upstreamStarted, "upstream did not become READY")
	cancelParent()
	waitTask7ThirdSignal(t, upstreamDone, "upstream did not observe parent cancellation")
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	frame, readErr := wire.ReadUOTFrame(clientConn)
	if readErr == nil && frame.Kind == wire.UOTFrameClose {
		t.Fatal("parent cancellation propagated a bare cause and wrote typed CLOSE")
	}
	if readErr == nil {
		t.Fatalf("unexpected frame after forced parent cancellation: %+v", frame)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("flow setup write = %v", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop after shutdown")
	}
}

func TestTask7ThirdReviewFinishedTransportStopsParentBridge(t *testing.T) {
	type contextKey struct{}
	parent, cancelParent := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "value"))
	tracker := newTaskTracker()
	ctx, finish, err := tracker.StartTransport(parent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ctx.Value(contextKey{}); got != "value" {
		t.Fatalf("tracked value = %v, want value", got)
	}
	finish()
	cancelParent()
	select {
	case <-ctx.Done():
		t.Fatalf("finished transport bridge propagated late parent cancellation: %v", context.Cause(ctx))
	case <-time.After(20 * time.Millisecond):
	}
}

func TestTask7ThirdReviewTCPListenerOwnershipRejectsDifferentServe(t *testing.T) {
	handler, config := newFlowTestHandler(t, noopUpstream{}, Timeouts{Shutdown: time.Second})
	server := &Server{config: config, handler: handler}
	first := newTask7ThirdBlockingListener()
	second := &task7ThirdCountingListener{}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { _ = first.Close() }) }
	t.Cleanup(release)

	firstDone := make(chan error, 1)
	go func() { firstDone <- server.Serve(context.Background(), first) }()
	waitTask7ThirdSignal(t, first.acceptEntered, "first Serve did not enter Accept")
	if err := server.Serve(context.Background(), second); err == nil {
		t.Fatal("different concurrent listener was not rejected")
	}
	if got := second.acceptCalls.Load(); got != 0 {
		t.Fatalf("conflicting listener Accept calls = %d, want 0", got)
	}
	if got := second.closeCalls.Load(); got != 1 {
		t.Fatalf("conflicting listener Close calls = %d, want 1", got)
	}
	if got := first.closeCalls.Load(); got != 0 {
		t.Fatalf("owned listener closed during conflict: calls=%d", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first Serve = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first Serve did not stop")
	}
	if got := first.closeCalls.Load(); got != 1 {
		t.Fatalf("owned listener Close calls = %d, want 1", got)
	}
}

func TestTask7ThirdReviewTCPListenerOwnershipSameServeIsIdempotent(t *testing.T) {
	handler, config := newFlowTestHandler(t, noopUpstream{}, Timeouts{Shutdown: time.Second})
	server := &Server{config: config, handler: handler}
	listener := newTask7ThirdBlockingListener()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { _ = listener.Close() }) }
	t.Cleanup(release)

	firstDone := make(chan error, 1)
	go func() { firstDone <- server.Serve(context.Background(), listener) }()
	waitTask7ThirdSignal(t, listener.acceptEntered, "first Serve did not enter Accept")
	secondDone := make(chan error, 1)
	go func() { secondDone <- server.Serve(context.Background(), listener) }()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("same-listener Serve = %v", err)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("same-listener Serve started a second Accept loop")
	}
	if got := listener.acceptCalls.Load(); got != 1 {
		t.Fatalf("same listener Accept calls = %d, want 1", got)
	}
	if got := listener.closeCalls.Load(); got != 0 {
		t.Fatalf("same listener was closed during idempotent reuse: calls=%d", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first Serve = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first Serve did not stop")
	}
	if got := listener.closeCalls.Load(); got != 1 {
		t.Fatalf("same listener Close calls = %d, want 1", got)
	}
}

func TestTask7ThirdReviewListenAndServeInstallShutdownBeforeServeClosesOnce(t *testing.T) {
	handler, config := newFlowTestHandler(t, noopUpstream{}, Timeouts{Shutdown: time.Second})
	server := &Server{config: config, handler: handler}
	listener := newTask7ThirdBlockingListener()
	installed, err := server.installTCPListener(listener)
	if err != nil {
		t.Fatal(err)
	}
	if installed != tcpListenerInstalled {
		t.Fatalf("install result = %v, want installed", installed)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if err := server.serveTCP(context.Background(), listener); err != nil {
		t.Fatalf("post-install Serve = %v", err)
	}
	if err := server.Serve(context.Background(), listener); err != nil {
		t.Fatalf("same owned listener after shutdown = %v", err)
	}
	if got := listener.acceptCalls.Load(); got != 1 {
		t.Fatalf("Accept calls across install/shutdown/Serve = %d, want 1", got)
	}
	if got := listener.closeCalls.Load(); got != 1 {
		t.Fatalf("Close calls across install/shutdown/Serve = %d, want 1", got)
	}
}

func TestTask7ThirdReviewHandlerSecondaryShutdownUsesOwnDeadline(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{FlowPair: time.Minute})
	writer := newTask7ReReviewReleaseWriteConn()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(writer.release) }) }
	t.Cleanup(release)
	claim := task6Claim(
		wire.SessionID{0xa2}, 1, 0, wire.FlowRoleAttach, wire.CarrierTCP,
		task6Metadata(wire.FlowKindTCP, wire.CarrierUDP, wire.CarrierTCP),
	)
	claim.Stream = writer
	go func() { _, _ = handler.claims.Submit(context.Background(), claim) }()
	waitTask6Entries(t, handler.claims, 1)

	firstDone := make(chan error, 1)
	go func() { firstDone <- handler.Shutdown(context.Background()) }()
	waitTask7ThirdSignal(t, writer.writeEntered, "first Shutdown did not block in claim cleanup")
	secondCtx, secondCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer secondCancel()
	secondDone := make(chan error, 1)
	go func() { secondDone <- handler.Shutdown(secondCtx) }()
	select {
	case err := <-secondDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("second Shutdown = %v, want own deadline", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("second Shutdown ignored its own deadline")
	}
	select {
	case err := <-firstDone:
		t.Fatalf("second deadline canceled first cleanup: %v", err)
	default:
	}
	release()
	if err := <-firstDone; err != nil {
		t.Fatalf("first Shutdown = %v", err)
	}
}

func TestTask7ThirdReviewServerSecondaryCloseUsesOwnDeadline(t *testing.T) {
	handler, config := newFlowTestHandler(t, noopUpstream{}, Timeouts{Shutdown: 25 * time.Millisecond})
	listener := newTask7ReReviewBlockingCloseListener()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(listener.release) }) }
	t.Cleanup(release)
	server := &Server{config: config, handler: handler, listener: listener}
	firstDone := make(chan error, 1)
	go func() { firstDone <- server.Shutdown(context.Background()) }()
	waitTask7ThirdSignal(t, listener.closeEntered, "first Shutdown did not block in listener Close")
	secondDone := make(chan error, 1)
	go func() { secondDone <- server.Close() }()
	select {
	case err := <-secondDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("secondary Close = %v, want own deadline", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("secondary Close ignored its own deadline")
	}
	select {
	case err := <-firstDone:
		t.Fatalf("secondary deadline canceled first cleanup: %v", err)
	default:
	}
	release()
	if err := <-firstDone; err != nil {
		t.Fatalf("first Shutdown = %v", err)
	}
}

func waitTask7ThirdSignal(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func waitTask7ThirdCondition(t *testing.T, condition func() bool, message string) {
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

type task7ThirdBlockingCloseSender struct {
	entered    chan struct{}
	exited     chan struct{}
	closed     chan struct{}
	enterOnce  sync.Once
	exitOnce   sync.Once
	abortOnce  sync.Once
	abortCalls atomic.Int32
}

func newTask7ThirdBlockingCloseSender() *task7ThirdBlockingCloseSender {
	return &task7ThirdBlockingCloseSender{
		entered: make(chan struct{}), exited: make(chan struct{}), closed: make(chan struct{}),
	}
}
func (s *task7ThirdBlockingCloseSender) Send(frame []byte) error {
	decoded, err := wire.DecodeUDPFrame(frame)
	if err != nil {
		return err
	}
	if decoded.Type != wire.UDPFrameClose {
		return errors.New("unexpected non-CLOSE datagram")
	}
	s.enterOnce.Do(func() { close(s.entered) })
	<-s.closed
	s.exitOnce.Do(func() { close(s.exited) })
	return net.ErrClosed
}
func (s *task7ThirdBlockingCloseSender) Abort() {
	s.abortOnce.Do(func() {
		s.abortCalls.Add(1)
		close(s.closed)
	})
}

type task7ThirdMultiFlowQuicConn struct {
	mu               sync.Mutex
	streams          []QuicStream
	datagrams        chan []byte
	closed           chan struct{}
	closeSendEntered chan struct{}
	closeSendExited  chan struct{}
	closeOnce        sync.Once
	closeSendOnce    sync.Once
	closeExitOnce    sync.Once
	closeCalls       atomic.Int32
}

func newTask7ThirdMultiFlowQuicConn(streams ...QuicStream) *task7ThirdMultiFlowQuicConn {
	return &task7ThirdMultiFlowQuicConn{
		streams: append([]QuicStream(nil), streams...), datagrams: make(chan []byte, 1),
		closed: make(chan struct{}), closeSendEntered: make(chan struct{}), closeSendExited: make(chan struct{}),
	}
}

func (c *task7ThirdMultiFlowQuicConn) AcceptStream(ctx context.Context) (QuicStream, error) {
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

func (c *task7ThirdMultiFlowQuicConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case data := <-c.datagrams:
		return append([]byte(nil), data...), nil
	case <-c.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *task7ThirdMultiFlowQuicConn) OfferDatagram(data []byte) {
	c.datagrams <- append([]byte(nil), data...)
}

func (c *task7ThirdMultiFlowQuicConn) SendDatagram(data []byte) error {
	frame, err := wire.DecodeUDPFrame(data)
	if err != nil {
		return err
	}
	if frame.Type != wire.UDPFrameClose {
		return nil
	}
	c.closeSendOnce.Do(func() { close(c.closeSendEntered) })
	<-c.closed
	c.closeExitOnce.Do(func() { close(c.closeSendExited) })
	return net.ErrClosed
}

func (c *task7ThirdMultiFlowQuicConn) CloseWithError(uint64, string) error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *task7ThirdMultiFlowQuicConn) Close() error {
	return c.CloseWithError(uint64(wire.CloseErrCodeOK), "")
}

func (*task7ThirdMultiFlowQuicConn) Context() context.Context { return context.Background() }
func (*task7ThirdMultiFlowQuicConn) LocalAddr() net.Addr      { return &net.UDPAddr{} }
func (*task7ThirdMultiFlowQuicConn) RemoteAddr() net.Addr     { return &net.UDPAddr{} }

type task7ThirdCountingControl struct {
	closeCalls atomic.Int32
}

func (*task7ThirdCountingControl) Read([]byte) (int, error)         { return 0, io.EOF }
func (*task7ThirdCountingControl) Write(p []byte) (int, error)      { return len(p), nil }
func (c *task7ThirdCountingControl) Close() error                   { c.closeCalls.Add(1); return nil }
func (*task7ThirdCountingControl) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*task7ThirdCountingControl) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*task7ThirdCountingControl) SetDeadline(time.Time) error      { return nil }
func (*task7ThirdCountingControl) SetReadDeadline(time.Time) error  { return nil }
func (*task7ThirdCountingControl) SetWriteDeadline(time.Time) error { return nil }

type task7ThirdSingleConnListener struct {
	connections chan net.Conn
	closed      chan struct{}
	closeOnce   sync.Once
}

func newTask7ThirdSingleConnListener() *task7ThirdSingleConnListener {
	return &task7ThirdSingleConnListener{connections: make(chan net.Conn, 1), closed: make(chan struct{})}
}
func (l *task7ThirdSingleConnListener) Offer(conn net.Conn) { l.connections <- conn }
func (l *task7ThirdSingleConnListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *task7ThirdSingleConnListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}
func (*task7ThirdSingleConnListener) Addr() net.Addr { return &net.TCPAddr{} }

type task7ThirdBlockingListener struct {
	acceptEntered chan struct{}
	closed        chan struct{}
	acceptOnce    sync.Once
	closeOnce     sync.Once
	acceptCalls   atomic.Int32
	closeCalls    atomic.Int32
}

func newTask7ThirdBlockingListener() *task7ThirdBlockingListener {
	return &task7ThirdBlockingListener{acceptEntered: make(chan struct{}), closed: make(chan struct{})}
}
func (l *task7ThirdBlockingListener) Accept() (net.Conn, error) {
	l.acceptCalls.Add(1)
	l.acceptOnce.Do(func() { close(l.acceptEntered) })
	<-l.closed
	return nil, net.ErrClosed
}
func (l *task7ThirdBlockingListener) Close() error {
	l.closeOnce.Do(func() {
		l.closeCalls.Add(1)
		close(l.closed)
	})
	return nil
}
func (*task7ThirdBlockingListener) Addr() net.Addr { return &net.TCPAddr{} }

type task7ThirdCountingListener struct {
	acceptCalls atomic.Int32
	closeCalls  atomic.Int32
}

func (l *task7ThirdCountingListener) Accept() (net.Conn, error) {
	l.acceptCalls.Add(1)
	return nil, net.ErrClosed
}
func (l *task7ThirdCountingListener) Close() error {
	l.closeCalls.Add(1)
	return nil
}
func (*task7ThirdCountingListener) Addr() net.Addr { return &net.TCPAddr{} }

var (
	_ QuicConn     = (*task7ThirdMultiFlowQuicConn)(nil)
	_ net.Conn     = (*task7ThirdCountingControl)(nil)
	_ net.Listener = (*task7ThirdSingleConnListener)(nil)
	_ net.Listener = (*task7ThirdBlockingListener)(nil)
	_ net.Listener = (*task7ThirdCountingListener)(nil)
)
