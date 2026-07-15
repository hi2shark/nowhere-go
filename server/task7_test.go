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

	carrierquic "github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/diagnostic"
	"github.com/hi2shark/nowhere-go/internal/udpassembly"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestUDPReassemblerOutOfOrderUsesSharedAssembly(t *testing.T) {
	now := time.Unix(100, 0)
	budget := &byteBudget{limit: 32}
	reassembler := newUDPReassembler(4, time.Minute, budget)

	outcome := reassembler.Push(1, testUDPFragment(7, 1, 2, 4, "cd"), now)
	if outcome.Complete || outcome.Dropped {
		t.Fatalf("first outcome = %+v", outcome)
	}
	outcome = reassembler.Push(1, testUDPFragment(7, 0, 2, 4, "ab"), now)
	if !outcome.Complete || outcome.Dropped || !bytes.Equal(outcome.Packet, []byte("abcd")) {
		t.Fatalf("completed outcome = %+v", outcome)
	}
	outcome.Release()
	assertTask7Budget(t, budget, 0)
}

func TestUDPReassemblerEmptyPacketUsesMinimumBudget(t *testing.T) {
	budget := &byteBudget{limit: 1}
	reassembler := newUDPReassembler(1, time.Minute, budget)
	outcome := reassembler.Push(1, testUDPFragment(1, 0, 1, 0, ""), time.Unix(100, 0))
	if !outcome.Complete || outcome.Dropped || outcome.Packet == nil || len(outcome.Packet) != 0 {
		t.Fatalf("empty outcome = %+v", outcome)
	}
	assertTask7Budget(t, budget, 1)
	outcome.Release()
	assertTask7Budget(t, budget, 0)
}

func TestUDPReassemblerRejectsBudgetOverflow(t *testing.T) {
	budget := &byteBudget{limit: 3}
	reassembler := newUDPReassembler(2, time.Minute, budget)
	now := time.Unix(100, 0)
	if outcome := reassembler.Push(1, testUDPFragment(1, 0, 2, 4, "ab"), now); outcome.Dropped {
		t.Fatalf("first fragment dropped: %+v", outcome)
	}
	outcome := reassembler.Push(2, testUDPFragment(1, 0, 2, 4, "cd"), now)
	if !outcome.Dropped || outcome.Complete {
		t.Fatalf("overflow outcome = %+v", outcome)
	}
	assertTask7Budget(t, budget, 2)
}

func TestUDPReassemblerRemoveFlow(t *testing.T) {
	budget := &byteBudget{limit: 16}
	reassembler := newUDPReassembler(4, time.Minute, budget)
	now := time.Unix(100, 0)
	_ = reassembler.Push(1, testUDPFragment(1, 0, 2, 4, "ab"), now)
	completed := reassembler.Push(1, testUDPFragment(2, 0, 1, 2, "cd"), now)
	_ = reassembler.Push(2, testUDPFragment(1, 0, 2, 4, "ef"), now)
	assertTask7Budget(t, budget, 6)

	reassembler.RemoveFlow(1)
	assertTask7Budget(t, budget, 2)
	completed.Release()
	assertTask7Budget(t, budget, 2)
}

func TestUDPReassemblerExpiresAtTTL(t *testing.T) {
	clock := &task7FakeClock{now: time.Unix(100, 0)}
	budget := &byteBudget{limit: 16}
	reassembler := newUDPReassembler(2, 10*time.Second, budget)
	_ = reassembler.Push(1, testUDPFragment(1, 0, 2, 4, "ab"), clock.Now())
	clock.Advance(10 * time.Second)
	reassembler.Expire(clock.Now())
	assertTask7Budget(t, budget, 0)
	if len(reassembler.slots) != 0 {
		t.Fatalf("slots after expiry = %d", len(reassembler.slots))
	}
}

func TestUDPReassemblerIdenticalDuplicateIsIdempotent(t *testing.T) {
	budget := &byteBudget{limit: 16}
	reassembler := newUDPReassembler(2, time.Minute, budget)
	now := time.Unix(100, 0)
	fragment := testUDPFragment(1, 0, 2, 4, "ab")
	_ = reassembler.Push(1, fragment, now)
	outcome := reassembler.Push(1, fragment, now)
	if outcome.Complete || outcome.Dropped {
		t.Fatalf("duplicate outcome = %+v", outcome)
	}
	assertTask7Budget(t, budget, 2)
	outcome = reassembler.Push(1, testUDPFragment(1, 1, 2, 4, "cd"), now)
	if !outcome.Complete || outcome.Dropped || string(outcome.Packet) != "abcd" {
		t.Fatalf("completion after duplicate = %+v", outcome)
	}
	outcome.Release()
	assertTask7Budget(t, budget, 0)
}

func TestUDPReassemblerConflictingDuplicateDropsSlot(t *testing.T) {
	first := testUDPFragment(1, 0, 2, 4, "ab")
	packet, _, err := udpassembly.NewPacket(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := packet.Push(testUDPFragment(1, 0, 2, 4, "zz")); !errors.Is(err, udpassembly.ErrDuplicateConflict) {
		t.Fatalf("shared assembly error = %v, want ErrDuplicateConflict", err)
	}

	budget := &byteBudget{limit: 16}
	reassembler := newUDPReassembler(2, time.Minute, budget)
	now := time.Unix(100, 0)
	_ = reassembler.Push(1, first, now)
	outcome := reassembler.Push(1, testUDPFragment(1, 0, 2, 4, "zz"), now)
	if !outcome.Dropped || outcome.Complete {
		t.Fatalf("conflict outcome = %+v", outcome)
	}
	assertTask7Budget(t, budget, 0)
	if len(reassembler.slots) != 0 {
		t.Fatalf("conflicting slot retained: %d", len(reassembler.slots))
	}
}

func TestUDPReassemblerMetadataConflictDropsSlot(t *testing.T) {
	first := testUDPFragment(1, 0, 2, 4, "ab")
	packet, _, err := udpassembly.NewPacket(first)
	if err != nil {
		t.Fatal(err)
	}
	conflict := testUDPFragment(1, 1, 3, 6, "cd")
	if _, err := packet.Push(conflict); !errors.Is(err, udpassembly.ErrMetadataConflict) {
		t.Fatalf("shared assembly error = %v, want ErrMetadataConflict", err)
	}

	budget := &byteBudget{limit: 16}
	reassembler := newUDPReassembler(2, time.Minute, budget)
	now := time.Unix(100, 0)
	_ = reassembler.Push(1, first, now)
	outcome := reassembler.Push(1, conflict, now)
	if !outcome.Dropped || outcome.Complete {
		t.Fatalf("metadata conflict outcome = %+v", outcome)
	}
	assertTask7Budget(t, budget, 0)
	if len(reassembler.slots) != 0 {
		t.Fatalf("metadata-conflicting slot retained: %d", len(reassembler.slots))
	}
}

func TestUDPReassemblerEvictsOldestAtSlotLimit(t *testing.T) {
	clock := &task7FakeClock{now: time.Unix(100, 0)}
	budget := &byteBudget{limit: 16}
	reassembler := newUDPReassembler(1, time.Minute, budget)
	_ = reassembler.Push(1, testUDPFragment(1, 0, 2, 4, "ab"), clock.Now())
	clock.Advance(time.Second)
	_ = reassembler.Push(2, testUDPFragment(1, 0, 2, 4, "cd"), clock.Now())

	if len(reassembler.slots) != 1 {
		t.Fatalf("slot count = %d, want 1", len(reassembler.slots))
	}
	if _, ok := reassembler.slots[reassemblyKey{flowID: 2, packetID: 1}]; !ok {
		t.Fatalf("newest slot missing: %+v", reassembler.slots)
	}
	assertTask7Budget(t, budget, 2)
}

func TestUDPReassemblerCompletedPacketRetainsBudgetUntilRelease(t *testing.T) {
	budget := &byteBudget{limit: 3}
	reassembler := newUDPReassembler(1, time.Second, budget)
	now := time.Unix(100, 0)
	outcome := reassembler.Push(1, testUDPFragment(1, 0, 1, 3, "abc"), now)
	if !outcome.Complete || outcome.Release == nil {
		t.Fatalf("completed outcome = %+v", outcome)
	}
	assertTask7Budget(t, budget, 3)
	reassembler.Expire(now.Add(time.Hour))
	assertTask7Budget(t, budget, 3)
	if second := reassembler.Push(2, testUDPFragment(1, 0, 1, 1, "x"), now); !second.Dropped {
		t.Fatalf("completed reservation did not constrain budget: %+v", second)
	}
	outcome.Release()
	outcome.Release()
	assertTask7Budget(t, budget, 0)
}

func TestUOTTypedDataPreservesEmptyPacket(t *testing.T) {
	encoded, err := wire.EncodeUOTFrame(wire.UOTFrame{Kind: wire.UOTFrameData, Payload: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	uplink := newTCPUDPUplink(newTask7MemoryConn(encoded))
	packet, err := uplink.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if packet == nil || len(packet) != 0 {
		t.Fatalf("empty DATA payload = %#v, want non-nil empty packet", packet)
	}
}

func TestUOTRejectsUnexpectedControlOnUplink(t *testing.T) {
	for _, frame := range []wire.UOTFrame{
		{Kind: wire.UOTFrameReady},
		{Kind: wire.UOTFrameReject, Code: wire.FlowErrorCodeDialFailed},
	} {
		encoded, err := wire.EncodeUOTFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		uplink := newTCPUDPUplink(newTask7MemoryConn(encoded))
		if _, err := uplink.ReadPacket(); !errors.Is(err, wire.ErrInvalidUOTFrame) {
			t.Fatalf("ReadPacket(%v) = %v, want ErrInvalidUOTFrame", frame.Kind, err)
		}
	}
}

func TestUOTSelectedDownlinkWritesReadyRejectAndClose(t *testing.T) {
	t.Run("ready-close", func(t *testing.T) {
		conn := newTask7MemoryConn(nil)
		result := newSetupResult(conn, wire.FlowKindUDP, wire.CarrierTCP)
		if err := result.ready(); err != nil {
			t.Fatal(err)
		}
		packetConn := newPairedUDPConn(&pairedUDP{
			FlowID: 1, Target: "example.com:53", Uplink: task7EmptyUplink{},
			Downlink: newTCPUDPDownlink(conn), IdleTimeout: time.Minute,
		})
		packetConn.(*pairedUDPConn).markReady()
		if err := packetConn.Close(); err != nil {
			t.Fatal(err)
		}
		reader := bytes.NewReader(conn.Bytes())
		assertTask7UOTFrame(t, reader, wire.UOTFrame{Kind: wire.UOTFrameReady})
		assertTask7UOTFrame(t, reader, wire.UOTFrame{Kind: wire.UOTFrameClose})
		if reader.Len() != 0 {
			t.Fatalf("unexpected trailing downlink bytes: %d", reader.Len())
		}
	})
	t.Run("reject", func(t *testing.T) {
		conn := newTask7MemoryConn(nil)
		result := newSetupResult(conn, wire.FlowKindUDP, wire.CarrierTCP)
		if err := result.reject(wire.FlowErrorCodeDialFailed); err != nil {
			t.Fatal(err)
		}
		reader := bytes.NewReader(conn.Bytes())
		assertTask7UOTFrame(t, reader, wire.UOTFrame{Kind: wire.UOTFrameReject, Code: wire.FlowErrorCodeDialFailed})
		if reader.Len() != 0 {
			t.Fatalf("unexpected trailing reject bytes: %d", reader.Len())
		}
	})
}

func TestHandlerAcceptsDuplexUDPOverTCP(t *testing.T) {
	readDone := make(chan error, 1)
	handler, config := newFlowTestHandler(t, upstreamFuncs{
		packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, target string, readiness FlowReadiness) error {
			if target != "example.com:53" {
				return errors.New("unexpected target")
			}
			if err := readiness.Ready(); err != nil {
				return err
			}
			buffer := make([]byte, 1)
			n, _, err := pc.ReadFrom(buffer)
			if err == nil && n != 0 {
				err = errors.New("empty packet was not preserved")
			}
			readDone <- err
			return pc.Close()
		},
	}, Timeouts{})
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 71, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	}
	client, handled := startTCPFlow(t, handler, config, wire.SessionID{0x71}, header, "example.com:53")
	defer client.Close()
	assertTask7UOTFrame(t, client, wire.UOTFrame{Kind: wire.UOTFrameReady})
	if err := wire.WriteUOTFrame(client, wire.UOTFrame{Kind: wire.UOTFrameData, Payload: []byte{}}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("duplex UoT packet was not dispatched")
	}
	assertTask7UOTFrame(t, client, wire.UOTFrame{Kind: wire.UOTFrameClose})
	select {
	case err := <-handled:
		if err != nil {
			t.Fatalf("HandleConn = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HandleConn did not return")
	}
}

func TestQUICDatagramUnknownFlowDropped(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{})
	conn := &task7PMTUQuicConn{maxima: []int{1200}}
	session := newPortalSession(wire.SessionID{0x72}, conn, handler, &net.UDPAddr{})
	frames, err := wire.EncodeUDPDataFragments(999, 1, []byte("unknown"), 1200)
	if err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames {
		session.handleDatagram(context.Background(), frame)
	}
	if _, sent := conn.snapshot(); len(sent) != 0 {
		t.Fatalf("unknown flow caused outbound datagrams: %d", len(sent))
	}
	assertTask7Budget(t, session.reassembler.budget, 0)
}

func TestQUICDatagramDoesNotCreateFlow(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{})
	session := newPortalSession(wire.SessionID{0x73}, &task7PMTUQuicConn{maxima: []int{1200}}, handler, &net.UDPAddr{})
	frames, err := wire.EncodeUDPDataFragments(1, 1, []byte("data"), 1200)
	if err != nil {
		t.Fatal(err)
	}
	session.handleDatagram(context.Background(), frames[0])
	session.mu.Lock()
	flowCount := len(session.flows)
	session.mu.Unlock()
	if flowCount != 0 {
		t.Fatalf("DATAGRAM created %d flows", flowCount)
	}
	handler.claims.mu.Lock()
	claimCount := len(handler.claims.entries)
	handler.claims.mu.Unlock()
	if claimCount != 0 {
		t.Fatalf("DATAGRAM created %d claims", claimCount)
	}
}

func TestQUICReliableControlPrecedesData(t *testing.T) {
	packets := make(chan net.PacketConn, 1)
	handler, config := newFlowTestHandler(t, upstreamFuncs{
		packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
			if err := readiness.Ready(); err != nil {
				return err
			}
			packets <- pc
			return nil
		},
	}, Timeouts{})
	conn := &task7PMTUQuicConn{maxima: []int{1200}}
	session := newPortalSession(wire.SessionID{0x74}, conn, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(session); err != nil {
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
	control := newTask7FINStream(setup)
	done := make(chan struct{})
	go func() {
		session.handleStream(context.Background(), control)
		close(done)
	}()

	select {
	case <-control.finWaitStarted:
	case <-packets:
		t.Fatal("flow activated before client send-side FIN")
	case <-time.After(time.Second):
		t.Fatal("control neither waited for FIN nor activated")
	}
	frames, err := wire.EncodeUDPDataFragments(header.FlowID, 1, []byte("early"), 1200)
	if err != nil {
		t.Fatal(err)
	}
	session.handleDatagram(context.Background(), frames[0])
	select {
	case <-packets:
		t.Fatal("early DATA activated or reached the flow")
	default:
	}
	close(control.fin)
	var pc net.PacketConn
	select {
	case pc = <-packets:
	case <-time.After(time.Second):
		t.Fatal("flow did not activate after FIN")
	}
	_ = pc.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("control handler did not return")
	}
}

func TestQUICUDPFragmentReassemblyDispatchesPacket(t *testing.T) {
	_, session, pc := startTask7QUICUDPFlow(t, &task7PMTUQuicConn{maxima: []int{1200}})
	frames, err := wire.EncodeUDPDataFragments(1, 7, []byte("fragmented"), nowuDataHeaderLen+4)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(frames) - 1; i >= 0; i-- {
		session.handleDatagram(context.Background(), frames[i])
	}
	buffer := make([]byte, 32)
	if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := pc.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "fragmented" {
		t.Fatalf("reassembled payload = %q", got)
	}
	_ = pc.Close()
}

func TestQUICUDPDownlinkRefreshesMTUAndRetriesOnce(t *testing.T) {
	tooLarge := &carrierquic.DatagramTooLargeError{MaxDatagramSize: nowuDataHeaderLen + 3, Cause: errors.New("pmtu")}
	conn := &task7PMTUQuicConn{
		maxima:     []int{nowuDataHeaderLen + 4, nowuDataHeaderLen + 3},
		sendErrors: []error{tooLarge},
	}
	_, _, pc := startTask7QUICUDPFlow(t, conn)
	if n, err := pc.WriteTo([]byte("abcdef"), &net.UDPAddr{}); err != nil || n != 6 {
		t.Fatalf("WriteTo = %d, %v", n, err)
	}
	maxCalls, sent := conn.snapshot()
	if maxCalls != 2 {
		t.Fatalf("CurrentMaxDatagramSize calls = %d, want 2", maxCalls)
	}
	if len(sent) != 3 {
		t.Fatalf("send attempts = %d, want 3", len(sent))
	}
	first, err := wire.DecodeUDPFrame(sent[0])
	if err != nil {
		t.Fatal(err)
	}
	retry0, err := wire.DecodeUDPFrame(sent[1])
	if err != nil {
		t.Fatal(err)
	}
	retry1, err := wire.DecodeUDPFrame(sent[2])
	if err != nil {
		t.Fatal(err)
	}
	if first.Fragment.PacketID == retry0.Fragment.PacketID || retry0.Fragment.PacketID != retry1.Fragment.PacketID {
		t.Fatalf("packet IDs = %d, %d, %d; retry must use one new ID", first.Fragment.PacketID, retry0.Fragment.PacketID, retry1.Fragment.PacketID)
	}
	_ = pc.Close()
}

func TestQUICUDPDownlinkSecondTooLargeDropsPacketWithoutClosingFlow(t *testing.T) {
	conn := &task7PMTUQuicConn{
		maxima: []int{nowuDataHeaderLen + 4, nowuDataHeaderLen + 3, nowuDataHeaderLen + 16},
		sendErrors: []error{
			&carrierquic.DatagramTooLargeError{MaxDatagramSize: nowuDataHeaderLen + 3, Cause: errors.New("first")},
			&carrierquic.DatagramTooLargeError{MaxDatagramSize: nowuDataHeaderLen + 2, Cause: errors.New("second")},
		},
	}
	_, _, pc := startTask7QUICUDPFlow(t, conn)
	if n, err := pc.WriteTo([]byte("abcdef"), &net.UDPAddr{}); err != nil || n != 6 {
		t.Fatalf("first WriteTo = %d, %v", n, err)
	}
	if n, err := pc.WriteTo([]byte("ok"), &net.UDPAddr{}); err != nil || n != 2 {
		t.Fatalf("flow closed after second TooLarge: WriteTo = %d, %v", n, err)
	}
	_ = pc.Close()
}

func TestQUICCloseReleasesFlowPermitAndReassemblyBudget(t *testing.T) {
	handler, session, pc := startTask7QUICUDPFlow(t, &task7PMTUQuicConn{maxima: []int{1200}})
	frames, err := wire.EncodeUDPDataFragments(1, 1, []byte("abcd"), nowuDataHeaderLen+2)
	if err != nil {
		t.Fatal(err)
	}
	session.handleDatagram(context.Background(), frames[0])
	empty, err := wire.EncodeUDPDataFragments(1, 2, []byte{}, 1200)
	if err != nil {
		t.Fatal(err)
	}
	session.handleDatagram(context.Background(), empty[0])
	assertTask7Budget(t, session.reassembler.budget, 3)
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	assertTask7SessionResources(t, handler, session)
}

func TestQUICReplacementRejectsPendingAndCancelsActive(t *testing.T) {
	type routedFlow struct {
		ctx context.Context
		pc  net.PacketConn
	}
	routed := make(chan routedFlow, 1)
	pairWait := make(chan struct{})
	var pairWaitOnce sync.Once
	config, err := NewConfig(ConfigOptions{
		Password: "secret", Timeouts: Timeouts{FlowPair: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{
		Config: config,
		Upstream: upstreamFuncs{
			packet: func(ctx context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
				if err := readiness.Ready(); err != nil {
					return err
				}
				routed <- routedFlow{ctx: ctx, pc: pc}
				return nil
			},
		},
		Observer: diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
			if event.Code == "pair_wait" && event.FlowID == 2 {
				pairWaitOnce.Do(func() { close(pairWait) })
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	sessionID := wire.SessionID{0x75}
	old := newPortalSession(sessionID, &task7PMTUQuicConn{maxima: []int{1200}}, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(old); err != nil {
		t.Fatal(err)
	}
	activeHeader := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}
	activeSetup, err := wire.EncodeFlowSetup(activeHeader, "example.com:53", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	old.handleStream(context.Background(), newRecordingQuicStream(activeSetup))
	active := <-routed
	partial, err := wire.EncodeUDPDataFragments(1, 1, []byte("abcd"), nowuDataHeaderLen+2)
	if err != nil {
		t.Fatal(err)
	}
	old.handleDatagram(context.Background(), partial[0])
	assertTask7Budget(t, old.reassembler.budget, 2)

	pendingHeader := wire.FlowHeader{
		Role: wire.FlowRoleAttach, FlowID: 2, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	}
	pendingSetup, err := wire.EncodeFlowSetup(pendingHeader, "", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	pendingControl := newRecordingQuicStream(pendingSetup)
	pendingDone := make(chan struct{})
	go func() {
		old.handleStream(context.Background(), pendingControl)
		close(pendingDone)
	}()
	select {
	case <-pairWait:
	case <-time.After(time.Second):
		t.Fatal("pending claim did not emit pair_wait")
	}

	replacement := newPortalSession(sessionID, &task7PMTUQuicConn{maxima: []int{1200}}, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(replacement); err != nil {
		t.Fatal(err)
	}
	select {
	case <-active.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("active flow context was not canceled by replacement")
	}
	select {
	case <-pendingDone:
	case <-time.After(time.Second):
		t.Fatal("pending control was not released by replacement")
	}
	assertFlowResult(t, bytes.NewReader(pendingControl.writtenBytes()), wire.FlowResult{
		Status: wire.FlowStatusReject,
		Code:   wire.FlowErrorCodeSessionReplaced,
	})
	assertTask7Budget(t, old.reassembler.budget, 0)
	assertTask7SessionResources(t, handler, old)
	_ = active.pc.Close()
}

func TestConfigTimeoutsReturnsNormalizedShutdown(t *testing.T) {
	defaultConfig, err := NewConfig(ConfigOptions{Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if got := defaultConfig.Timeouts().Shutdown; got != DefaultShutdownTimeout {
		t.Fatalf("default shutdown timeout = %v, want %v", got, DefaultShutdownTimeout)
	}
	explicitConfig, err := NewConfig(ConfigOptions{
		Password: "secret", Timeouts: Timeouts{Shutdown: 73 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	timeouts := explicitConfig.Timeouts()
	if timeouts.Shutdown != 73*time.Millisecond {
		t.Fatalf("explicit shutdown timeout = %v", timeouts.Shutdown)
	}
	timeouts.Shutdown = time.Second
	if got := explicitConfig.Timeouts().Shutdown; got != 73*time.Millisecond {
		t.Fatalf("Timeouts did not return by value: %v", got)
	}
}

func TestFlowReadinessOnReadyRegistrationConcurrentResolution(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	callback := make(chan struct{})
	readiness := newFlowReadiness(func() error {
		close(entered)
		<-release
		return nil
	}, nil)
	readyDone := make(chan error, 1)
	go func() { readyDone <- readiness.Ready() }()
	<-entered
	registered := make(chan struct{})
	go func() {
		readiness.setOnReady(func() { close(callback) })
		close(registered)
	}()
	<-registered
	close(release)
	select {
	case <-callback:
	case <-time.After(time.Second):
		t.Fatal("onReady callback was lost during concurrent resolution")
	}
	if err := <-readyDone; err != nil {
		t.Fatal(err)
	}

	resolved := newFlowReadiness(nil, nil)
	if err := resolved.Ready(); err != nil {
		t.Fatal(err)
	}
	immediate := make(chan struct{})
	resolved.setOnReady(func() { close(immediate) })
	select {
	case <-immediate:
	default:
		t.Fatal("onReady callback was not invoked after ready resolution")
	}
}

func TestHandlerShutdownUsesCallerContext(t *testing.T) {
	handler := newTask7ShutdownHandler(t, 5*time.Millisecond)
	_, finish, err := handler.tasks.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = handler.Shutdown(ctx)
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want caller deadline", err)
	}
	assertTask7Duration(t, elapsed, 30*time.Millisecond, 150*time.Millisecond)
}

func TestServerShutdownUsesSingleAbsoluteDeadline(t *testing.T) {
	handler := newTask7ShutdownHandler(t, 80*time.Millisecond)
	_, finish, err := handler.tasks.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	recorder := &task7CloseRecorder{}
	server := &Server{
		config: handler.config, handler: handler,
		listener:     &task7CountingListener{name: "tcp", recorder: recorder},
		quicListener: &task7CountingQuicListener{name: "quic", recorder: recorder},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = server.Shutdown(ctx)
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want caller deadline", err)
	}
	assertTask7Duration(t, elapsed, 20*time.Millisecond, 100*time.Millisecond)
	if got := recorder.Events(); !equalTask7Strings(got, []string{"tcp", "quic"}) {
		t.Fatalf("shutdown close order = %v, want [tcp quic]", got)
	}
}

func TestHandlerCloseUsesConfiguredShutdownTimeout(t *testing.T) {
	short := measureTask7HandlerClose(t, 25*time.Millisecond)
	long := measureTask7HandlerClose(t, 80*time.Millisecond)
	assertTask7Duration(t, short, 15*time.Millisecond, 100*time.Millisecond)
	assertTask7Duration(t, long, 60*time.Millisecond, 180*time.Millisecond)
	if long-short < 30*time.Millisecond {
		t.Fatalf("per-instance handler Close timeouts not distinguished: short=%v long=%v", short, long)
	}
}

func TestServerCloseUsesConfiguredShutdownTimeout(t *testing.T) {
	short := measureTask7ServerClose(t, 25*time.Millisecond)
	long := measureTask7ServerClose(t, 80*time.Millisecond)
	assertTask7Duration(t, short, 15*time.Millisecond, 100*time.Millisecond)
	assertTask7Duration(t, long, 60*time.Millisecond, 180*time.Millisecond)
	if long-short < 30*time.Millisecond {
		t.Fatalf("per-instance server Close timeouts not distinguished: short=%v long=%v", short, long)
	}
}

func TestServerShutdownForcesRemainingTasksAfterDeadline(t *testing.T) {
	handler := newTask7ShutdownHandler(t, time.Second)
	_, finish, err := handler.tasks.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	server := &Server{config: handler.config, handler: handler}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := server.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want deadline", err)
	}
	handler.tasks.mu.Lock()
	remaining := len(handler.tasks.tasks)
	closed := handler.tasks.closed
	handler.tasks.mu.Unlock()
	if remaining != 0 || !closed {
		t.Fatalf("tracker after forced shutdown: remaining=%d closed=%v", remaining, closed)
	}
}

func TestServerShutdownReleasesClaimsPermitsAndReassembly(t *testing.T) {
	handler, session, _ := startTask7QUICUDPFlow(t, &task7PMTUQuicConn{maxima: []int{1200}})
	frames, err := wire.EncodeUDPDataFragments(1, 1, []byte("abcd"), nowuDataHeaderLen+2)
	if err != nil {
		t.Fatal(err)
	}
	session.handleDatagram(context.Background(), frames[0])
	assertTask7Budget(t, session.reassembler.budget, 2)
	server := &Server{config: handler.config, handler: handler}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	assertTask7SessionResources(t, handler, session)
}

func TestServerCloseIsIdempotent(t *testing.T) {
	handler := newTask7ShutdownHandler(t, 25*time.Millisecond)
	recorder := &task7CloseRecorder{}
	tcpListener := &task7CountingListener{name: "tcp", recorder: recorder}
	quicListener := &task7CountingQuicListener{name: "quic", recorder: recorder}
	server := &Server{
		config: handler.config, handler: handler,
		listener: tcpListener, quicListener: quicListener,
	}
	if err := server.Close(); err != nil {
		t.Fatalf("first Close = %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	if tcpListener.count.Load() != 1 || quicListener.count.Load() != 1 {
		t.Fatalf("listener close counts: tcp=%d quic=%d", tcpListener.count.Load(), quicListener.count.Load())
	}
	if got := recorder.Events(); !equalTask7Strings(got, []string{"tcp", "quic"}) {
		t.Fatalf("idempotent close events = %v", got)
	}
}

func TestServerListenAndServeQUICUsesShutdownPath(t *testing.T) {
	config, err := NewConfig(ConfigOptions{
		Password: "secret", Networks: []Network{NetworkUDP}, Timeouts: Timeouts{Shutdown: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &task7CloseRecorder{}
	listener := &task7CountingQuicListener{name: "quic", recorder: recorder}
	server := &Server{config: config, handler: handler, quicListener: listener}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.ListenAndServe(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListenAndServe = %v, want context.Canceled", err)
	}
	if listener.count.Load() != 1 {
		t.Fatalf("QUIC listener close count = %d", listener.count.Load())
	}
	handler.tasks.mu.Lock()
	closed := handler.tasks.closed
	handler.tasks.mu.Unlock()
	if !closed {
		t.Fatal("handler did not enter shutdown")
	}
}

func newTask7ShutdownHandler(t *testing.T, timeout time.Duration) *Handler {
	t.Helper()
	config, err := NewConfig(ConfigOptions{
		Password: "secret", Networks: []Network{NetworkTCP}, Timeouts: Timeouts{Shutdown: timeout},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func measureTask7HandlerClose(t *testing.T, timeout time.Duration) time.Duration {
	t.Helper()
	handler := newTask7ShutdownHandler(t, timeout)
	_, finish, err := handler.tasks.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	started := time.Now()
	err = handler.Close()
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Handler.Close(%v) = %v, want deadline", timeout, err)
	}
	return elapsed
}

func measureTask7ServerClose(t *testing.T, timeout time.Duration) time.Duration {
	t.Helper()
	handler := newTask7ShutdownHandler(t, timeout)
	_, finish, err := handler.tasks.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	server := &Server{config: handler.config, handler: handler}
	started := time.Now()
	err = server.Close()
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Server.Close(%v) = %v, want deadline", timeout, err)
	}
	return elapsed
}

func assertTask7Duration(t *testing.T, got, minimum, maximum time.Duration) {
	t.Helper()
	if got < minimum || got > maximum {
		t.Fatalf("duration = %v, want [%v, %v]", got, minimum, maximum)
	}
}

func equalTask7Strings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func startTask7QUICUDPFlow(t *testing.T, conn *task7PMTUQuicConn) (*Handler, *portalSession, net.PacketConn) {
	t.Helper()
	packets := make(chan net.PacketConn, 1)
	handler, config := newFlowTestHandler(t, upstreamFuncs{
		packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
			if err := readiness.Ready(); err != nil {
				return err
			}
			packets <- pc
			return nil
		},
	}, Timeouts{})
	session := newPortalSession(wire.SessionID{0x76}, conn, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(session); err != nil {
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
	control := newRecordingQuicStream(setup)
	session.handleStream(context.Background(), control)
	assertFlowResult(t, bytes.NewReader(control.writtenBytes()), wire.FlowResult{Status: wire.FlowStatusReady})
	select {
	case pc := <-packets:
		return handler, session, pc
	case <-time.After(time.Second):
		t.Fatal("QUIC UDP flow did not reach upstream")
		return nil, nil, nil
	}
}

func assertTask7SessionResources(t *testing.T, handler *Handler, session *portalSession) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.tasks.Wait(ctx); err != nil {
		t.Fatalf("tracked tasks did not finish: %v", err)
	}
	assertTask7Budget(t, session.reassembler.budget, 0)
	session.mu.Lock()
	flows := len(session.flows)
	queued := session.queuedBytes
	session.mu.Unlock()
	if flows != 0 || queued != 0 {
		t.Fatalf("session resources: flows=%d queued=%d", flows, queued)
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

func assertTask7UOTFrame(t *testing.T, reader io.Reader, want wire.UOTFrame) {
	t.Helper()
	if conn, ok := reader.(net.Conn); ok {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	}
	got, err := wire.ReadUOTFrame(reader)
	if err != nil {
		t.Fatalf("ReadUOTFrame = %v", err)
	}
	if got.Kind != want.Kind || got.Code != want.Code ||
		(want.Kind == wire.UOTFrameData && !bytes.Equal(got.Payload, want.Payload)) {
		t.Fatalf("UOT frame = %+v, want %+v", got, want)
	}
}

type task7EmptyUplink struct{}

func (task7EmptyUplink) ReadPacket() ([]byte, error) { return nil, io.EOF }
func (task7EmptyUplink) Close() error                { return nil }

type task7MemoryConn struct {
	reader *bytes.Reader
	mu     sync.Mutex
	writer bytes.Buffer
	closed atomic.Bool
}

func newTask7MemoryConn(input []byte) *task7MemoryConn {
	return &task7MemoryConn{reader: bytes.NewReader(input)}
}

func (c *task7MemoryConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *task7MemoryConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writer.Write(p)
}
func (c *task7MemoryConn) Close() error {
	c.closed.Store(true)
	return nil
}
func (c *task7MemoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *task7MemoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *task7MemoryConn) SetDeadline(time.Time) error      { return nil }
func (c *task7MemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *task7MemoryConn) SetWriteDeadline(time.Time) error { return nil }
func (c *task7MemoryConn) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.writer.Bytes()...)
}

type task7FINStream struct {
	reader         *bytes.Reader
	fin            chan struct{}
	finWaitStarted chan struct{}
	waitOnce       sync.Once
	closeOnce      sync.Once
}

func newTask7FINStream(input []byte) *task7FINStream {
	return &task7FINStream{
		reader: bytes.NewReader(input), fin: make(chan struct{}), finWaitStarted: make(chan struct{}),
	}
}

func (s *task7FINStream) Read(p []byte) (int, error) {
	if s.reader.Len() > 0 {
		return s.reader.Read(p)
	}
	s.waitOnce.Do(func() { close(s.finWaitStarted) })
	<-s.fin
	return 0, io.EOF
}
func (s *task7FINStream) Write(p []byte) (int, error)      { return len(p), nil }
func (s *task7FINStream) Close() error                     { s.closeOnce.Do(func() {}); return nil }
func (s *task7FINStream) SetDeadline(time.Time) error      { return nil }
func (s *task7FINStream) SetReadDeadline(time.Time) error  { return nil }
func (s *task7FINStream) SetWriteDeadline(time.Time) error { return nil }
func (s *task7FINStream) CancelRead(uint64)                {}
func (s *task7FINStream) CancelWrite(uint64)               {}

type task7PMTUQuicConn struct {
	mu         sync.Mutex
	maxima     []int
	maxCalls   int
	sendErrors []error
	sent       [][]byte
	closed     atomic.Int32
}

func (c *task7PMTUQuicConn) AcceptStream(ctx context.Context) (QuicStream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *task7PMTUQuicConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *task7PMTUQuicConn) SendDatagram(frame []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, append([]byte(nil), frame...))
	if len(c.sendErrors) == 0 {
		return nil
	}
	err := c.sendErrors[0]
	c.sendErrors = c.sendErrors[1:]
	return err
}
func (c *task7PMTUQuicConn) CurrentMaxDatagramSize() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := c.maxCalls
	c.maxCalls++
	if len(c.maxima) == 0 {
		return 1200
	}
	if index >= len(c.maxima) {
		index = len(c.maxima) - 1
	}
	return c.maxima[index]
}
func (c *task7PMTUQuicConn) CloseWithError(uint64, string) error { c.closed.Add(1); return nil }
func (c *task7PMTUQuicConn) Close() error                        { c.closed.Add(1); return nil }
func (c *task7PMTUQuicConn) Context() context.Context            { return context.Background() }
func (c *task7PMTUQuicConn) LocalAddr() net.Addr                 { return &net.UDPAddr{} }
func (c *task7PMTUQuicConn) RemoteAddr() net.Addr                { return &net.UDPAddr{} }
func (c *task7PMTUQuicConn) snapshot() (int, [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	frames := make([][]byte, len(c.sent))
	for i := range c.sent {
		frames[i] = append([]byte(nil), c.sent[i]...)
	}
	return c.maxCalls, frames
}

type task7CloseRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *task7CloseRecorder) Add(event string) {
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
}

func (r *task7CloseRecorder) Events() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

type task7CountingListener struct {
	name     string
	recorder *task7CloseRecorder
	once     sync.Once
	count    atomic.Int32
}

func (*task7CountingListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *task7CountingListener) Close() error {
	l.once.Do(func() {
		l.count.Add(1)
		l.recorder.Add(l.name)
	})
	return nil
}
func (*task7CountingListener) Addr() net.Addr { return &net.TCPAddr{} }

type task7CountingQuicListener struct {
	name     string
	recorder *task7CloseRecorder
	once     sync.Once
	count    atomic.Int32
}

func (*task7CountingQuicListener) Accept(ctx context.Context) (QuicConn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (l *task7CountingQuicListener) Close() error {
	l.once.Do(func() {
		l.count.Add(1)
		l.recorder.Add(l.name)
	})
	return nil
}

var (
	_ net.Conn   = (*task7MemoryConn)(nil)
	_ QuicStream = (*task7FINStream)(nil)
	_ QuicConn   = (*task7PMTUQuicConn)(nil)
)

type task7FakeClock struct {
	now time.Time
}

func (c *task7FakeClock) Now() time.Time { return c.now }
func (c *task7FakeClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

func testUDPFragment(packetID uint32, fragmentID, fragmentCount uint8, totalLen uint16, payload string) wire.UDPFragment {
	return wire.UDPFragment{
		PacketID:      packetID,
		FragmentID:    fragmentID,
		FragmentCount: fragmentCount,
		TotalLen:      totalLen,
		Payload:       []byte(payload),
	}
}

func assertTask7Budget(t *testing.T, budget *byteBudget, want int) {
	t.Helper()
	budget.mu.Lock()
	got := budget.used
	budget.mu.Unlock()
	if got != want {
		t.Fatalf("budget used = %d, want %d", got, want)
	}
}
