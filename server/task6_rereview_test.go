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

	"github.com/hi2shark/nowhere-go/diagnostic"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestQUICGenerationNotReusedAfterUnregisterReconnect(t *testing.T) {
	pairWait := make(chan diagnostic.Event, 1)
	var upstreamCalls atomic.Int32
	handler, config := newTask6RereviewHandler(t, upstreamFuncs{
		stream: func(_ context.Context, _ net.Conn, _ net.Addr, _ string, readiness FlowReadiness) error {
			upstreamCalls.Add(1)
			return readiness.Ready()
		},
	}, Timeouts{FlowPair: time.Second}, pairWait)
	sessionID := wire.SessionID{0x81}
	oldSession := registerTask6Session(t, handler, sessionID)
	oldGeneration := oldSession.Generation
	oldSession.Close()
	handler.sessions.Unregister(oldSession)

	newSession := registerTask6Session(t, handler, sessionID)
	header := wire.FlowHeader{
		Role: wire.FlowRoleOpen, FlowID: 1, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	}
	tcpClient, tcpDone := startTCPFlow(t, handler, config, sessionID, header, "example.com:443")
	defer tcpClient.Close()
	waitTask6PairWait(t, pairWait, header.FlowID)

	header.Role = wire.FlowRoleAttach
	setup, err := wire.EncodeFlowSetup(header, "", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	oldControl := newRecordingQuicStream(setup)
	oldSession.handleStream(context.Background(), oldControl)
	assertFlowResult(t, bytes.NewReader(oldControl.writtenBytes()), wire.FlowResult{
		Status: wire.FlowStatusReject,
		Code:   wire.FlowErrorCodeMetadataConflict,
	})
	if newSession.Generation == oldGeneration {
		t.Fatalf("reconnected generation reused token %d", oldGeneration)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("delayed old stream reached upstream %d times", got)
	}

	_ = handler.Close()
	select {
	case err := <-tcpDone:
		if err == nil {
			t.Fatal("pending TCP half unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("pending TCP half did not stop")
	}
}

func TestFirstQUICSessionAdoptsLiveTCPProvisionalGeneration(t *testing.T) {
	pairWait := make(chan diagnostic.Event, 1)
	var upstreamCalls atomic.Int32
	handler, config := newTask6RereviewHandler(t, upstreamFuncs{
		stream: func(_ context.Context, _ net.Conn, _ net.Addr, _ string, readiness FlowReadiness) error {
			upstreamCalls.Add(1)
			return readiness.Ready()
		},
	}, Timeouts{FlowPair: time.Second}, pairWait)
	sessionID := wire.SessionID{0x82}
	header := wire.FlowHeader{
		Role: wire.FlowRoleOpen, FlowID: 1, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	}
	tcpClient, tcpDone := startTCPFlow(t, handler, config, sessionID, header, "example.com:443")
	defer tcpClient.Close()
	waitTask6PairWait(t, pairWait, header.FlowID)

	handler.claims.mu.Lock()
	entry := handler.claims.entries[claimKey{sessionID: sessionID, flowID: header.FlowID}]
	var provisional uint64
	if entry != nil {
		provisional = entry.generation
	}
	handler.claims.mu.Unlock()
	if provisional == 0 {
		t.Fatal("TCP half did not create a provisional generation")
	}

	session := registerTask6Session(t, handler, sessionID)
	if session.Generation != provisional {
		t.Fatalf("first QUIC generation = %d, want provisional %d", session.Generation, provisional)
	}

	header.Role = wire.FlowRoleAttach
	setup, err := wire.EncodeFlowSetup(header, "", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	control := newRecordingQuicStream(setup)
	session.handleStream(context.Background(), control)
	assertFlowResult(t, bytes.NewReader(control.writtenBytes()), wire.FlowResult{Status: wire.FlowStatusReady})
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
	select {
	case err := <-tcpDone:
		if err != nil {
			t.Fatalf("provisional TCP half = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("provisional TCP half did not pair")
	}
}

func TestRealQUICNOWUDuplicateUsesMetadataConflict(t *testing.T) {
	t.Run("open-open", func(t *testing.T) {
		pairWait := make(chan diagnostic.Event, 1)
		var upstreamCalls atomic.Int32
		handler, config := newTask6RereviewHandler(t, upstreamFuncs{
			packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
				upstreamCalls.Add(1)
				if err := readiness.Ready(); err != nil {
					return err
				}
				return pc.Close()
			},
		}, Timeouts{FlowPair: time.Second}, pairWait)
		sessionID := wire.SessionID{0x83}
		session := registerTask6Session(t, handler, sessionID)
		header := wire.FlowHeader{
			Role: wire.FlowRoleOpen, FlowID: 1, Kind: wire.FlowKindUDP,
			Uplink: wire.CarrierUDP, Downlink: wire.CarrierTCP,
		}
		setup, err := wire.EncodeFlowSetup(header, "example.com:53", config.EffectiveSpec())
		if err != nil {
			t.Fatal(err)
		}
		firstControl := newRecordingQuicStream(setup)
		firstDone := make(chan struct{})
		go func() {
			session.handleStream(context.Background(), firstControl)
			close(firstDone)
		}()
		waitTask6PairWait(t, pairWait, header.FlowID)
		original := session.getFlow(header.FlowID)
		if original == nil {
			t.Fatal("original QUIC Open flow missing")
		}

		duplicate := newRecordingQuicStream(setup)
		session.handleStream(context.Background(), duplicate)
		assertFlowResult(t, bytes.NewReader(duplicate.writtenBytes()), wire.FlowResult{
			Status: wire.FlowStatusReject,
			Code:   wire.FlowErrorCodeMetadataConflict,
		})
		assertTask6OriginalNOWUFlowAlive(t, session, header.FlowID, original)
		if got := upstreamCalls.Load(); got != 0 {
			t.Fatalf("duplicate Open reached upstream before pair: %d", got)
		}

		header.Role = wire.FlowRoleAttach
		tcpClient, tcpDone := startTCPFlow(t, handler, config, sessionID, header, "")
		defer tcpClient.Close()
		assertTask6UOTFrame(t, tcpClient, wire.UOTFrame{Kind: wire.UOTFrameReady})
		select {
		case err := <-tcpDone:
			if err != nil {
				t.Fatalf("TCP Attach = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("TCP Attach did not return")
		}
		select {
		case <-firstDone:
		case <-time.After(time.Second):
			t.Fatal("original QUIC Open did not finish")
		}
		if got := upstreamCalls.Load(); got != 1 {
			t.Fatalf("upstream calls = %d, want 1", got)
		}
	})

	t.Run("duplex-duplex", func(t *testing.T) {
		packets := make(chan net.PacketConn, 1)
		var upstreamCalls atomic.Int32
		handler, config := newTask6RereviewHandler(t, upstreamFuncs{
			packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
				upstreamCalls.Add(1)
				if err := readiness.Ready(); err != nil {
					return err
				}
				packets <- pc
				return nil
			},
		}, Timeouts{}, nil)
		session := registerTask6Session(t, handler, wire.SessionID{0x84})
		header := wire.FlowHeader{
			Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindUDP,
			Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
		}
		setup, err := wire.EncodeFlowSetup(header, "example.com:53", config.EffectiveSpec())
		if err != nil {
			t.Fatal(err)
		}
		firstControl := newRecordingQuicStream(setup)
		session.handleStream(context.Background(), firstControl)
		assertFlowResult(t, bytes.NewReader(firstControl.writtenBytes()), wire.FlowResult{Status: wire.FlowStatusReady})
		packet := receiveTask6Packet(t, packets)
		original := session.getFlow(header.FlowID)
		if original == nil {
			t.Fatal("original QUIC Duplex flow missing")
		}

		duplicate := newRecordingQuicStream(setup)
		session.handleStream(context.Background(), duplicate)
		assertFlowResult(t, bytes.NewReader(duplicate.writtenBytes()), wire.FlowResult{
			Status: wire.FlowStatusReject,
			Code:   wire.FlowErrorCodeMetadataConflict,
		})
		assertTask6OriginalNOWUFlowAlive(t, session, header.FlowID, original)
		if got := upstreamCalls.Load(); got != 1 {
			t.Fatalf("duplicate Duplex reached upstream: calls=%d", got)
		}
		if err := packet.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestClaimRegistryTerminalFIFOIgnoresRemovedPointers(t *testing.T) {
	limits := task6Limits(2)
	limits.PendingFlowsPerSession = 4
	registry := newClaimRegistry(20*time.Millisecond, limits)
	defer registry.Close()

	sessions := []wire.SessionID{{0x91}, {0x92}, {0x93}, {0x94}, {0x95}}
	original := &wire.FlowError{Code: wire.FlowErrorCodeInvalidRequest}
	for _, sessionID := range sessions[:4] {
		registry.Reject(sessionID, 1, registry.CurrentGeneration(sessionID), original)
	}
	registry.ReplaceSession(sessions[1], 100, ErrClosed)
	registry.Reject(sessions[4], 1, registry.CurrentGeneration(sessions[4]), ErrPairTimeout)

	late := task6Claim(sessions[0], 1, registry.CurrentGeneration(sessions[0]), wire.FlowRoleAttach, wire.CarrierUDP,
		task6Metadata(wire.FlowKindTCP, wire.CarrierTCP, wire.CarrierUDP))
	if _, err := registry.Submit(context.Background(), late); setupFailureCode(err) != wire.FlowErrorCodeInvalidRequest {
		t.Fatalf("late A rejection = %v (%v), want original invalid_request", err, setupFailureCode(err))
	}
	assertTask6F2(t, late.Stream.(*task6BufferConn).Bytes(), wire.FlowResult{
		Status: wire.FlowStatusReject,
		Code:   wire.FlowErrorCodeInvalidRequest,
	})
}

func TestSessionManagerReplacementWriterDoesNotBlockOtherSessionOperation(t *testing.T) {
	handler := newTask6Handler(t, noopUpstream{})
	blockedSessionID := wire.SessionID{0xa1}
	oldSession := registerTask6Session(t, handler, blockedSessionID)
	writer := newTask6BlockingWriteConn()
	pairWait := make(chan diagnostic.Event, 1)
	handler.claims.setObserver(diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
		if event.Code == "pair_wait" {
			select {
			case pairWait <- event:
			default:
			}
		}
	}))
	claim := flowClaim{
		SessionID: blockedSessionID, FlowID: 1, Generation: oldSession.Generation,
		Role: wire.FlowRoleAttach, Carrier: wire.CarrierTCP,
		Metadata: claimMetadata{Kind: wire.FlowKindTCP, Uplink: wire.CarrierUDP, Downlink: wire.CarrierTCP},
		Stream:   writer,
	}
	pendingDone := make(chan error, 1)
	go func() {
		_, err := handler.claims.Submit(context.Background(), claim)
		pendingDone <- err
	}()
	waitTask6PairWait(t, pairWait, claim.FlowID)

	replacement := newPortalSession(blockedSessionID, &fakeQuicConn{}, handler, &net.UDPAddr{})
	replaceDone := make(chan error, 1)
	go func() { replaceDone <- handler.sessions.Register(replacement) }()
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("replacement did not reach blocking selected writer")
	}

	otherDone := make(chan error, 1)
	go func() {
		other := newPortalSession(wire.SessionID{0xa2}, &fakeQuicConn{}, handler, &net.UDPAddr{})
		if err := handler.sessions.Register(other); err != nil {
			otherDone <- err
			return
		}
		handler.sessions.Unregister(other)
		otherDone <- nil
	}()
	var otherErr error
	otherCompleted := false
	select {
	case otherErr = <-otherDone:
		otherCompleted = true
	case <-time.After(100 * time.Millisecond):
	}

	newest := newPortalSession(blockedSessionID, &fakeQuicConn{}, handler, &net.UDPAddr{})
	newestDone := make(chan error, 1)
	go func() { newestDone <- handler.sessions.Register(newest) }()
	var newestErr error
	newestCompleted := false
	select {
	case newestErr = <-newestDone:
		newestCompleted = true
	case <-time.After(100 * time.Millisecond):
	}
	close(writer.release)

	select {
	case err := <-replaceDone:
		if err != nil {
			t.Fatalf("replacement Register = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement Register did not finish after writer release")
	}
	select {
	case err := <-pendingDone:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("pending replacement = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending claim did not finish")
	}
	if !otherCompleted {
		select {
		case otherErr = <-otherDone:
		case <-time.After(time.Second):
			t.Fatal("other session operation remained blocked")
		}
	}
	if !newestCompleted {
		select {
		case newestErr = <-newestDone:
		case <-time.After(time.Second):
			t.Fatal("newer same-ID registration remained blocked")
		}
	}
	if otherErr != nil {
		t.Fatalf("other session operation = %v", otherErr)
	}
	if newestErr != nil {
		t.Fatalf("newer same-ID registration = %v", newestErr)
	}
	if !otherCompleted || !newestCompleted {
		t.Fatal("blocking replacement writer held sessionManager.mu")
	}
	if current := handler.sessions.Current(blockedSessionID); current != newest {
		t.Fatalf("current session = %p, want newest %p", current, newest)
	}
	if newest.Generation == replacement.Generation {
		t.Fatalf("newer same-ID registration reused generation %d", newest.Generation)
	}
	if newest.Conn.(*fakeQuicConn).closed.Load() != 0 {
		t.Fatal("older cleanup closed the newest physical connection")
	}
	active, err := handler.claims.Submit(context.Background(), flowClaim{
		SessionID: blockedSessionID, FlowID: 2, Generation: newest.Generation, BoundGeneration: true,
		Role: wire.FlowRoleDuplex, Carrier: wire.CarrierUDP,
		Metadata: claimMetadata{Kind: wire.FlowKindTCP, Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP},
		Stream:   &task6BufferConn{},
	})
	if err != nil {
		t.Fatalf("newest generation claim = %v", err)
	}
	active.Release()
}

func newTask6RereviewHandler(t *testing.T, upstream Upstream, timeouts Timeouts, pairWait chan<- diagnostic.Event) (*Handler, *Config) {
	t.Helper()
	var observer diagnostic.Observer
	if pairWait != nil {
		observer = diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
			if event.Code != "pair_wait" {
				return
			}
			select {
			case pairWait <- event:
			default:
			}
		})
	}
	config, err := NewConfig(ConfigOptions{Password: "secret", Timeouts: timeouts, Limits: task6Limits(4)})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: upstream, Observer: observer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	return handler, config
}

func waitTask6PairWait(t *testing.T, events <-chan diagnostic.Event, flowID uint64) {
	t.Helper()
	select {
	case event := <-events:
		if event.FlowID != flowID {
			t.Fatalf("pair_wait flow = %d, want %d", event.FlowID, flowID)
		}
	case <-time.After(time.Second):
		t.Fatal("pair_wait event not observed")
	}
}

func assertTask6OriginalNOWUFlowAlive(t *testing.T, session *portalSession, flowID uint64, original *nowuFlow) {
	t.Helper()
	if current := session.getFlow(flowID); current != original {
		t.Fatalf("original NOWU flow replaced or removed: current=%p original=%p", current, original)
	}
	original.mu.Lock()
	closed := original.closed
	original.mu.Unlock()
	if closed {
		t.Fatal("duplicate closed the original NOWU flow")
	}
}

type task6BlockingWriteConn struct {
	task6BufferConn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newTask6BlockingWriteConn() *task6BlockingWriteConn {
	return &task6BlockingWriteConn{started: make(chan struct{}), release: make(chan struct{})}
}

func (c *task6BlockingWriteConn) Write(payload []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return c.task6BufferConn.Write(payload)
}
