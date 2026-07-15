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

func TestTask7ReviewDuplicateCandidatePreservesOriginalPartialReservation(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{UDPIdle: time.Minute})
	session := newPortalSession(wire.SessionID{0x81}, &task7PMTUQuicConn{}, handler, &net.UDPAddr{})
	original := newNowuFlow(session, 1, "example.com:53")
	if err := session.insertNOWUFlow(original); err != nil {
		t.Fatal(err)
	}
	original.deliverFragment(testUDPFragment(1, 0, 2, 4, "ab"))
	assertTask7Budget(t, session.budget, 2)

	candidate := newNowuFlow(session, 1, "example.com:53")
	if err := session.insertNOWUFlow(candidate); !errors.Is(err, ErrDuplicateHalf) {
		t.Fatalf("duplicate insert = %v, want ErrDuplicateHalf", err)
	}
	candidate.shutdown(ErrDuplicateHalf)
	assertTask7Budget(t, session.budget, 2)

	original.shutdown(net.ErrClosed)
	assertTask7Budget(t, session.budget, 0)
}

func TestTask7ReviewDuplicateCandidatePreservesOriginalCompletedReservation(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{UDPIdle: time.Minute})
	session := newPortalSession(wire.SessionID{0x82}, &task7PMTUQuicConn{}, handler, &net.UDPAddr{})
	original := newNowuFlow(session, 1, "example.com:53")
	if err := session.insertNOWUFlow(original); err != nil {
		t.Fatal(err)
	}
	original.deliverFragment(testUDPFragment(1, 0, 1, 2, "ab"))
	assertTask7Budget(t, session.budget, 2)

	candidate := newNowuFlow(session, 1, "example.com:53")
	if err := session.insertNOWUFlow(candidate); !errors.Is(err, ErrDuplicateHalf) {
		t.Fatalf("duplicate insert = %v, want ErrDuplicateHalf", err)
	}
	candidate.shutdown(ErrDuplicateHalf)
	assertTask7Budget(t, session.budget, 2)

	buffer := make([]byte, 2)
	n, _, err := original.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "ab" {
		t.Fatalf("packet = %q, want ab", got)
	}
	assertTask7Budget(t, session.budget, 0)
	original.shutdown(net.ErrClosed)
}

func TestTask7ReviewCloseWaitsForInFlightFragmentPush(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{UDPIdle: time.Minute})
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	handler.now = func() time.Time {
		once.Do(func() { close(entered) })
		<-release
		return time.Unix(100, 0)
	}
	session := newPortalSession(wire.SessionID{0x83}, &task7PMTUQuicConn{}, handler, &net.UDPAddr{})
	flow := newNowuFlow(session, 1, "example.com:53")
	if err := session.insertNOWUFlow(flow); err != nil {
		t.Fatal(err)
	}

	delivered := make(chan struct{})
	go func() {
		flow.deliverFragment(testUDPFragment(1, 0, 2, 4, "ab"))
		close(delivered)
	}()
	<-entered
	shutdown := make(chan struct{})
	go func() {
		flow.shutdown(net.ErrClosed)
		close(shutdown)
	}()
	select {
	case <-shutdown:
		t.Fatal("shutdown passed an in-flight fragment Push")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("fragment delivery did not resume")
	}
	select {
	case <-shutdown:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish")
	}
	assertTask7Budget(t, session.budget, 0)
	if len(session.reassembler.slots) != 0 {
		t.Fatalf("reassembly slots after shutdown = %d", len(session.reassembler.slots))
	}
	session.mu.Lock()
	flows := len(session.flows)
	session.mu.Unlock()
	if flows != 0 {
		t.Fatalf("flows after shutdown = %d", flows)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.tasks.Wait(ctx); err != nil {
		t.Fatalf("tasks after shutdown = %v", err)
	}
}

func TestTask7ReviewSessionDrivesReassemblyExpiry(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{UDPIdle: time.Minute})
	clock := &task7FakeClock{now: time.Unix(100, 0)}
	ticker := &task7ReviewTicker{ticks: make(chan time.Time, 1)}
	handler.now = clock.Now
	handler.newReassemblyTicker = func(time.Duration) reassemblyTicker { return ticker }
	session := newPortalSession(wire.SessionID{0x84}, &task7PMTUQuicConn{}, handler, &net.UDPAddr{})
	session.startReassemblyExpiry()
	flow := newNowuFlow(session, 1, "example.com:53")
	if err := session.insertNOWUFlow(flow); err != nil {
		t.Fatal(err)
	}
	flow.deliverFragment(testUDPFragment(1, 0, 2, 4, "ab"))
	assertTask7Budget(t, session.budget, 2)

	clock.Advance(nowuPartialTTL)
	ticker.ticks <- clock.Now()
	deadline := time.Now().Add(time.Second)
	for {
		session.reassembler.mu.Lock()
		slots := len(session.reassembler.slots)
		session.reassembler.mu.Unlock()
		if slots == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("wall-clock driver did not expire partial reassembly")
		}
		time.Sleep(time.Millisecond)
	}
	assertTask7Budget(t, session.budget, 0)
	session.Close()
	if !ticker.stopped.Load() {
		t.Fatal("session close did not stop reassembly ticker")
	}
}

func TestTask7ReviewPreactivationBuffersDataUntilControlFIN(t *testing.T) {
	packets := make(chan net.PacketConn, 1)
	handler, config := newFlowTestHandler(t, upstreamFuncs{
		packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
			if err := readiness.Ready(); err != nil {
				return err
			}
			packets <- pc
			return nil
		},
	}, Timeouts{RequestIdle: time.Minute, UDPIdle: time.Minute})
	session := newPortalSession(wire.SessionID{0x87}, &task7PMTUQuicConn{}, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}
	setup, err := wire.EncodeFlowSetup(header, "example.com:53", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	control := newTask7FINStream(setup)
	controlDone := make(chan struct{})
	go func() {
		session.handleStream(context.Background(), control)
		close(controlDone)
	}()
	select {
	case <-control.finWaitStarted:
	case <-time.After(time.Second):
		t.Fatal("control did not reach FIN wait")
	}
	frames, err := wire.EncodeUDPDataFragments(1, 1, []byte("early"), 1200)
	if err != nil {
		t.Fatal(err)
	}
	session.handleDatagram(context.Background(), frames[0])
	select {
	case <-packets:
		t.Fatal("flow dispatched before control FIN")
	default:
	}
	handler.claims.mu.Lock()
	claims := len(handler.claims.entries)
	permits := len(handler.claims.udpInUse)
	handler.claims.mu.Unlock()
	if claims != 0 || permits != 0 {
		t.Fatalf("preactivation created claims=%d permits=%d", claims, permits)
	}
	assertTask7Budget(t, session.reassembler.budget, 0)

	close(control.fin)
	var pc net.PacketConn
	select {
	case pc = <-packets:
	case <-time.After(time.Second):
		t.Fatal("flow did not dispatch after control FIN")
	}
	defer pc.Close()
	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 16)
	n, _, err := pc.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "early" {
		t.Fatalf("buffered packet = %q, want early", got)
	}
	select {
	case <-controlDone:
	case <-time.After(time.Second):
		t.Fatal("control handler did not return")
	}
}

func TestTask7ReviewPreactivationCleansFailedControlAndExpiresBounds(t *testing.T) {
	handler, config := newFlowTestHandler(t, noopUpstream{}, Timeouts{RequestIdle: time.Minute})
	clock := &task7FakeClock{now: time.Unix(100, 0)}
	handler.now = clock.Now
	session := newPortalSession(wire.SessionID{0x88}, &task7PMTUQuicConn{}, handler, &net.UDPAddr{})
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}
	setup, err := wire.EncodeFlowSetup(header, "example.com:53", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	invalid := newRecordingQuicStream(append(setup, 0xff))
	session.handleStream(context.Background(), invalid)
	session.mu.Lock()
	pending := len(session.pendingControls)
	frames := session.pendingFrames
	bytesUsed := session.pendingBytes
	session.mu.Unlock()
	if pending != 0 || frames != 0 || bytesUsed != 0 {
		t.Fatalf("failed control retained pending=%d frames=%d bytes=%d", pending, frames, bytesUsed)
	}

	header.FlowID = 2
	control, err := session.beginPendingUDPControl(header)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := wire.EncodeUDPDataFragments(2, 1, make([]byte, 1100), 1200)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := wire.DecodeUDPFrame(encoded[0])
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < preactivationDatagramLimit*2; i++ {
		decoded.Fragment.PacketID = uint32(i + 1)
		if !session.bufferPendingUDPData(decoded, len(encoded[0])) {
			t.Fatal("known pending control was not recognized")
		}
	}
	session.mu.Lock()
	frames = session.pendingFrames
	bytesUsed = session.pendingBytes
	session.mu.Unlock()
	if frames > preactivationDatagramLimit || bytesUsed > preactivationByteLimit {
		t.Fatalf("preactivation bounds exceeded: frames=%d bytes=%d", frames, bytesUsed)
	}
	if frames == 0 || bytesUsed == 0 {
		t.Fatal("preactivation buffer did not retain bounded DATA")
	}
	clock.Advance(preactivationTTL)
	session.expirePendingControls(clock.Now())
	session.mu.Lock()
	pending = len(session.pendingControls)
	frames = session.pendingFrames
	bytesUsed = session.pendingBytes
	session.mu.Unlock()
	if pending != 0 || frames != 0 || bytesUsed != 0 {
		t.Fatalf("expired control retained pending=%d frames=%d bytes=%d", pending, frames, bytesUsed)
	}
	session.cancelPendingUDPControl(header.FlowID, control)
}

func TestTask7ReviewQUICDownlinkSerializesPacketAndClose(t *testing.T) {
	recorder := &task7ReviewDatagramRecorder{
		firstData: make(chan struct{}),
		release:   make(chan struct{}),
	}
	base := newQUICUDPDownlink(nil, recorder.Send, func() int { return nowuDataHeaderLen + 2 })
	pc := newPairedUDPConn(&pairedUDP{
		FlowID: 1, Target: "example.com:53", Uplink: task7EmptyUplink{},
		Downlink: base, IdleTimeout: time.Minute,
	}).(*pairedUDPConn)
	pc.markReady()
	packetDone := make(chan error, 1)
	go func() {
		_, err := pc.WriteTo([]byte("abcd"), nil)
		packetDone <- err
	}()
	<-recorder.firstData
	closeDone := make(chan error, 1)
	go func() { closeDone <- pc.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close completed inside packet send: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(recorder.release)
	if err := <-packetDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if got, want := recorder.Types(), []wire.UDPFrameType{wire.UDPFrameData, wire.UDPFrameData, wire.UDPFrameClose}; !equalTask7ReviewFrameTypes(got, want) {
		t.Fatalf("frame order = %v, want %v", got, want)
	}
	if _, err := pc.WriteTo([]byte("later"), nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteTo after Close = %v, want net.ErrClosed", err)
	}
}

func TestTask7ReviewReadyUDPFlowWritesCloseForOrdinaryErrors(t *testing.T) {
	for _, cause := range []error{io.EOF, errors.New("upstream failed")} {
		t.Run(cause.Error(), func(t *testing.T) {
			conn := newTask7MemoryConn(nil)
			paired := newPairedUDPConn(&pairedUDP{
				FlowID: 1, Target: "example.com:53", Uplink: task7EmptyUplink{},
				Downlink: newTCPUDPDownlink(conn), IdleTimeout: time.Minute,
			}).(*pairedUDPConn)
			paired.markReady()
			paired.closeWithError(cause)
			assertTask7UOTFrame(t, bytes.NewReader(conn.Bytes()), wire.UOTFrame{Kind: wire.UOTFrameClose})
		})
	}
}

func TestTask7ReviewRealUpstreamsWriteCloseAfterReady(t *testing.T) {
	ordinary := errors.New("ordinary upstream failure")
	for _, tc := range []struct {
		name     string
		upstream Upstream
		wantErr  error
	}{
		{
			name: "dial-target-eof",
			upstream: NewDialUpstream(&task6Dialer{dial: func(context.Context, string, string) (net.Conn, error) {
				return &task7ReviewEOFConn{}, nil
			}}),
		},
		{
			name: "custom-upstream-error",
			upstream: upstreamFuncs{packet: func(_ context.Context, _ net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
				if err := readiness.Ready(); err != nil {
					return err
				}
				return ordinary
			}},
			wantErr: ordinary,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, config := newFlowTestHandler(t, tc.upstream, Timeouts{UDPIdle: time.Minute})
			header := wire.FlowHeader{
				Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindUDP,
				Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
			}
			client, done := startTCPFlow(t, handler, config, wire.SessionID{0x89}, header, "example.com:53")
			defer client.Close()
			assertTask7UOTFrame(t, client, wire.UOTFrame{Kind: wire.UOTFrameReady})
			assertTask7UOTFrame(t, client, wire.UOTFrame{Kind: wire.UOTFrameClose})
			select {
			case err := <-done:
				if tc.wantErr == nil && err != nil {
					t.Fatalf("ServeTCP = %v, want nil", err)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("ServeTCP = %v, want %v", err, tc.wantErr)
				}
			case <-time.After(time.Second):
				t.Fatal("ServeTCP did not finish")
			}
		})
	}
}

func TestTask7ReviewShutdownClosesPreRouteTCPTransports(t *testing.T) {
	for _, phase := range []string{"tls", "auth", "request"} {
		t.Run(phase, func(t *testing.T) {
			handler, config := newFlowTestHandler(t, noopUpstream{}, Timeouts{
				TLSHandshake: time.Minute, Auth: time.Minute, RequestIdle: time.Minute,
			})
			var prefix []byte
			if phase == "request" {
				var err error
				prefix, err = wire.MakeAuthFrameWithSession("secret", config.EffectiveSpec(), wire.SessionID{0x85})
				if err != nil {
					t.Fatal(err)
				}
			}
			conn := newTask7ReviewBlockingConn(prefix)
			handshake := func(_ context.Context, raw net.Conn) (net.Conn, error) {
				if phase == "tls" {
					_, err := raw.Read(make([]byte, 1))
					return nil, err
				}
				return raw, nil
			}
			serveDone := make(chan error, 1)
			go func() {
				serveDone <- handler.ServeTCP(context.Background(), conn, conn.RemoteAddr(), handshake, nil)
			}()
			select {
			case <-conn.readBlocked:
			case <-time.After(time.Second):
				t.Fatalf("%s phase did not block", phase)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := handler.Shutdown(ctx); err != nil {
				t.Fatalf("Shutdown during %s = %v", phase, err)
			}
			select {
			case <-serveDone:
			case <-time.After(time.Second):
				t.Fatalf("ServeTCP remained blocked during %s", phase)
			}
		})
	}
}

func TestTask7ReviewShutdownClosesPreAuthQUICTransport(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{Auth: time.Minute})
	conn := newTask7ReviewBlockingQuicConn()
	serveDone := make(chan error, 1)
	go func() { serveDone <- handler.ServeQUIC(context.Background(), conn) }()
	select {
	case <-conn.acceptStarted:
	case <-time.After(time.Second):
		t.Fatal("QUIC auth did not block in AcceptStream")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown during QUIC auth = %v", err)
	}
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("ServeQUIC remained blocked during auth")
	}
}

func TestTask7ReviewShutdownHonorsDeadlineDuringSelectedReject(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{FlowPair: time.Minute})
	writer := newTask7ReviewBlockingWriteConn()
	claim := task6Claim(
		wire.SessionID{0x86}, 1, 0, wire.FlowRoleAttach, wire.CarrierTCP,
		task6Metadata(wire.FlowKindTCP, wire.CarrierUDP, wire.CarrierTCP),
	)
	claim.Stream = writer
	submitDone := make(chan error, 1)
	go func() {
		_, err := handler.claims.Submit(context.Background(), claim)
		submitDone <- err
	}()
	waitTask6Entries(t, handler.claims, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := handler.Shutdown(ctx)
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want context deadline", err)
	}
	if elapsed < 15*time.Millisecond || elapsed > 200*time.Millisecond {
		t.Fatalf("Shutdown elapsed = %v, want caller-bounded duration", elapsed)
	}
	if !writer.closed.Load() {
		t.Fatal("caller deadline did not close blocked selected writer")
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

func TestTask7ReviewServeQUICSnapshotsListenerDuringShutdown(t *testing.T) {
	config, err := NewConfig(ConfigOptions{Password: "secret", Networks: []Network{NetworkUDP}})
	if err != nil {
		t.Fatal(err)
	}
	listener := &task7ReviewQuicListener{entered: make(chan struct{}), closed: make(chan struct{})}
	server, err := NewServer(ServerOptions{Config: config, Upstream: noopUpstream{}, QUICListener: listener})
	if err != nil {
		t.Fatal(err)
	}
	type serveResult struct {
		err   error
		panic any
	}
	done := make(chan serveResult, 1)
	go func() {
		result := serveResult{}
		defer func() {
			result.panic = recover()
			done <- result
		}()
		result.err = server.ServeQUIC(context.Background())
	}()
	<-listener.entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.panic != nil {
			t.Fatalf("ServeQUIC panicked after listener shutdown: %v", result.panic)
		}
		if result.err != nil {
			t.Fatalf("ServeQUIC = %v, want nil", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeQUIC did not stop after shutdown")
	}
}

type task7ReviewTicker struct {
	ticks   chan time.Time
	stopped atomic.Bool
}

func (t *task7ReviewTicker) Chan() <-chan time.Time { return t.ticks }
func (t *task7ReviewTicker) Stop()                  { t.stopped.Store(true) }

type task7ReviewDatagramRecorder struct {
	mu        sync.Mutex
	types     []wire.UDPFrameType
	firstData chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (r *task7ReviewDatagramRecorder) Send(frame []byte) error {
	decoded, err := wire.DecodeUDPFrame(frame)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.types = append(r.types, decoded.Type)
	r.mu.Unlock()
	if decoded.Type == wire.UDPFrameData {
		blocked := false
		r.once.Do(func() {
			blocked = true
			close(r.firstData)
		})
		if blocked {
			<-r.release
		}
	}
	return nil
}

func (r *task7ReviewDatagramRecorder) Types() []wire.UDPFrameType {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]wire.UDPFrameType(nil), r.types...)
}

func equalTask7ReviewFrameTypes(a, b []wire.UDPFrameType) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type task7ReviewBlockingConn struct {
	mu          sync.Mutex
	prefix      []byte
	readBlocked chan struct{}
	closed      chan struct{}
	readOnce    sync.Once
	closeOnce   sync.Once
}

func newTask7ReviewBlockingConn(prefix []byte) *task7ReviewBlockingConn {
	return &task7ReviewBlockingConn{
		prefix: append([]byte(nil), prefix...), readBlocked: make(chan struct{}), closed: make(chan struct{}),
	}
}

func (c *task7ReviewBlockingConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	c.readOnce.Do(func() { close(c.readBlocked) })
	<-c.closed
	return 0, net.ErrClosed
}
func (*task7ReviewBlockingConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *task7ReviewBlockingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (*task7ReviewBlockingConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*task7ReviewBlockingConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*task7ReviewBlockingConn) SetDeadline(time.Time) error      { return nil }
func (*task7ReviewBlockingConn) SetReadDeadline(time.Time) error  { return nil }
func (*task7ReviewBlockingConn) SetWriteDeadline(time.Time) error { return nil }

type task7ReviewBlockingWriteConn struct {
	closed   atomic.Bool
	closedCh chan struct{}
	once     sync.Once
}

func newTask7ReviewBlockingWriteConn() *task7ReviewBlockingWriteConn {
	return &task7ReviewBlockingWriteConn{closedCh: make(chan struct{})}
}
func (c *task7ReviewBlockingWriteConn) Read([]byte) (int, error) {
	<-c.closedCh
	return 0, net.ErrClosed
}
func (c *task7ReviewBlockingWriteConn) Write([]byte) (int, error) {
	<-c.closedCh
	return 0, net.ErrClosed
}
func (c *task7ReviewBlockingWriteConn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		close(c.closedCh)
	})
	return nil
}
func (*task7ReviewBlockingWriteConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*task7ReviewBlockingWriteConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*task7ReviewBlockingWriteConn) SetDeadline(time.Time) error      { return nil }
func (*task7ReviewBlockingWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*task7ReviewBlockingWriteConn) SetWriteDeadline(time.Time) error { return nil }

type task7ReviewEOFConn struct{}

func (*task7ReviewEOFConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*task7ReviewEOFConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*task7ReviewEOFConn) Close() error                     { return nil }
func (*task7ReviewEOFConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*task7ReviewEOFConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*task7ReviewEOFConn) SetDeadline(time.Time) error      { return nil }
func (*task7ReviewEOFConn) SetReadDeadline(time.Time) error  { return nil }
func (*task7ReviewEOFConn) SetWriteDeadline(time.Time) error { return nil }

type task7ReviewBlockingQuicConn struct {
	acceptStarted chan struct{}
	closed        chan struct{}
	acceptOnce    sync.Once
	closeOnce     sync.Once
}

func newTask7ReviewBlockingQuicConn() *task7ReviewBlockingQuicConn {
	return &task7ReviewBlockingQuicConn{acceptStarted: make(chan struct{}), closed: make(chan struct{})}
}
func (c *task7ReviewBlockingQuicConn) AcceptStream(context.Context) (QuicStream, error) {
	c.acceptOnce.Do(func() { close(c.acceptStarted) })
	<-c.closed
	return nil, net.ErrClosed
}
func (c *task7ReviewBlockingQuicConn) ReceiveDatagram(context.Context) ([]byte, error) {
	<-c.closed
	return nil, net.ErrClosed
}
func (*task7ReviewBlockingQuicConn) SendDatagram([]byte) error { return nil }
func (c *task7ReviewBlockingQuicConn) CloseWithError(uint64, string) error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *task7ReviewBlockingQuicConn) Close() error {
	return c.CloseWithError(0, "")
}
func (*task7ReviewBlockingQuicConn) Context() context.Context { return context.Background() }
func (*task7ReviewBlockingQuicConn) LocalAddr() net.Addr      { return &net.UDPAddr{} }
func (*task7ReviewBlockingQuicConn) RemoteAddr() net.Addr     { return &net.UDPAddr{} }

type task7ReviewQuicListener struct {
	entered chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (l *task7ReviewQuicListener) Accept(context.Context) (QuicConn, error) {
	l.once.Do(func() { close(l.entered) })
	<-l.closed
	return nil, errors.New("listener stopped")
}

func (l *task7ReviewQuicListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

var (
	_ = context.Background
	_ = io.EOF
	_ sync.Mutex
	_ atomic.Bool
)
