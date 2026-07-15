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

func TestConfig140Defaults(t *testing.T) {
	config, err := NewConfig(ConfigOptions{Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	timeouts := config.Timeouts()
	if timeouts.FlowPair != 15*time.Second || timeouts.Shutdown != 5*time.Second {
		t.Fatalf("timeouts = %+v", timeouts)
	}
	limits := config.Limits()
	if limits.PendingFlowsPerSession != 1024 || limits.UDPFlowsPerSession != 256 ||
		limits.UDPQueueBytes != 4*1024*1024 || limits.UDPQueuePackets != 64 ||
		limits.AuthenticatedTCPIdleConnections != 4096 {
		t.Fatalf("limits = %+v", limits)
	}
}

func TestConfigRejectsNegative140Limits(t *testing.T) {
	cases := []Limits{
		{PendingFlowsPerSession: -1},
		{UDPFlowsPerSession: -1},
		{UDPQueueBytes: -1},
		{UDPQueuePackets: -1},
		{ActiveQUICSessions: -1},
		{AuthenticatedTCPIdleConnections: -1},
		{MaxUnauthenticatedConnections: -1},
		{MaxUnauthenticatedPerSource: -1},
		{MaxConcurrentHandshakes: -1},
	}
	for _, limits := range cases {
		if _, err := NewConfig(ConfigOptions{Password: "secret", Limits: limits}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("limits %+v: error = %v, want ErrInvalidConfig", limits, err)
		}
	}
	if _, err := NewConfig(ConfigOptions{Password: "secret", Timeouts: Timeouts{Shutdown: -1}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("negative shutdown: error = %v, want ErrInvalidConfig", err)
	}
}

func TestTaskTrackerCloseWaitsForExistingAndRejectsNew(t *testing.T) {
	tracker := newTaskTracker()
	_, finish, err := tracker.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() {
		tracker.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned before the existing task finished")
	case <-time.After(20 * time.Millisecond):
	}
	if _, _, err := tracker.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Start after Close = %v, want ErrClosed", err)
	}
	finish()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not drain")
	}
}

func TestTaskTrackerCancelAllDrains(t *testing.T) {
	tracker := newTaskTracker()
	ctx, finish, err := tracker.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("replace")
	tracker.CancelAll(cause)
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), cause) {
			t.Fatalf("cause = %v, want %v", context.Cause(ctx), cause)
		}
	case <-time.After(time.Second):
		t.Fatal("tracked context was not canceled")
	}
	finish()
	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := tracker.Wait(waitCtx); err != nil {
		t.Fatalf("Wait = %v", err)
	}
}

func TestTaskTrackerWaitUsesCallerDeadline(t *testing.T) {
	tracker := newTaskTracker()
	_, finish, err := tracker.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := tracker.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("Wait ignored caller deadline: %v", elapsed)
	}
}

func TestClaimRegistryDuplexActivatesImmediately(t *testing.T) {
	registry := newClaimRegistry(time.Second, task6Limits(2))
	defer registry.Close()
	claim := task6Claim(wire.SessionID{1}, 1, 1, wire.FlowRoleDuplex, wire.CarrierTCP, task6Metadata(wire.FlowKindTCP, wire.CarrierTCP, wire.CarrierTCP))
	claim.Target = "example.com:443"
	active, err := registry.Submit(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || active.Target != claim.Target || active.Readiness == nil {
		t.Fatalf("active = %+v", active)
	}
	active.Release()
}

func TestClaimRegistryPairsOpenFirstAndAttachFirst(t *testing.T) {
	for _, firstRole := range []wire.FlowRole{wire.FlowRoleOpen, wire.FlowRoleAttach} {
		t.Run(flowRoleName(firstRole), func(t *testing.T) {
			registry := newClaimRegistry(time.Second, task6Limits(2))
			defer registry.Close()
			meta := task6Metadata(wire.FlowKindTCP, wire.CarrierTCP, wire.CarrierUDP)
			open := task6Claim(wire.SessionID{2}, 9, 1, wire.FlowRoleOpen, wire.CarrierTCP, meta)
			open.Target = "open.example:443"
			attach := task6Claim(wire.SessionID{2}, 9, 1, wire.FlowRoleAttach, wire.CarrierUDP, meta)
			first, second := open, attach
			if firstRole == wire.FlowRoleAttach {
				first, second = attach, open
			}
			firstDone := make(chan error, 1)
			go func() {
				active, err := registry.Submit(context.Background(), first)
				if active != nil {
					firstDone <- errors.New("first claim unexpectedly owned activation")
					return
				}
				firstDone <- err
			}()
			waitTask6Entries(t, registry, 1)
			active, err := registry.Submit(context.Background(), second)
			if err != nil {
				t.Fatal(err)
			}
			if active == nil || active.Target != open.Target {
				t.Fatalf("active target = %v", active)
			}
			if err := <-firstDone; err != nil {
				t.Fatal(err)
			}
			if active.Selected.Carrier != active.Metadata.Downlink {
				t.Fatalf("selected carrier = %v, downlink = %v", active.Selected.Carrier, active.Metadata.Downlink)
			}
			active.Release()
		})
	}
}

func TestClaimRegistryRejectsCrossKindAndDuplicateClaims(t *testing.T) {
	tests := []struct {
		name   string
		second flowClaim
	}{
		{
			name: "cross-kind",
			second: task6Claim(wire.SessionID{3}, 1, 1, wire.FlowRoleAttach, wire.CarrierUDP,
				task6Metadata(wire.FlowKindUDP, wire.CarrierTCP, wire.CarrierUDP)),
		},
		{
			name: "duplicate",
			second: task6Claim(wire.SessionID{3}, 1, 1, wire.FlowRoleOpen, wire.CarrierTCP,
				task6Metadata(wire.FlowKindTCP, wire.CarrierTCP, wire.CarrierUDP)),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registry := newClaimRegistry(time.Second, task6Limits(2))
			defer registry.Close()
			first := task6Claim(wire.SessionID{3}, 1, 1, wire.FlowRoleOpen, wire.CarrierTCP,
				task6Metadata(wire.FlowKindTCP, wire.CarrierTCP, wire.CarrierUDP))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			firstDone := make(chan error, 1)
			go func() {
				_, err := registry.Submit(ctx, first)
				firstDone <- err
			}()
			waitTask6Entries(t, registry, 1)
			if _, err := registry.Submit(context.Background(), tc.second); setupFailureCode(err) != wire.FlowErrorCodeMetadataConflict {
				t.Fatalf("second error = %v, code = %v", err, setupFailureCode(err))
			}
			if err := <-firstDone; setupFailureCode(err) != wire.FlowErrorCodeMetadataConflict {
				t.Fatalf("first error = %v, code = %v", err, setupFailureCode(err))
			}
		})
	}
}

func TestClaimRegistryLateAttachReceivesOriginalPairTimeout(t *testing.T) {
	registry := newClaimRegistry(20*time.Millisecond, task6Limits(2))
	defer registry.Close()
	meta := task6Metadata(wire.FlowKindTCP, wire.CarrierTCP, wire.CarrierUDP)
	open := task6Claim(wire.SessionID{4}, 1, 1, wire.FlowRoleOpen, wire.CarrierTCP, meta)
	if _, err := registry.Submit(context.Background(), open); !errors.Is(err, ErrPairTimeout) {
		t.Fatalf("open = %v, want ErrPairTimeout", err)
	}
	attach := task6Claim(wire.SessionID{4}, 1, 1, wire.FlowRoleAttach, wire.CarrierUDP, meta)
	start := time.Now()
	if _, err := registry.Submit(context.Background(), attach); !errors.Is(err, ErrPairTimeout) {
		t.Fatalf("late attach = %v, want original ErrPairTimeout", err)
	}
	if elapsed := time.Since(start); elapsed >= 15*time.Millisecond {
		t.Fatalf("late attach started a new pair timeout: %v", elapsed)
	}
	assertTask6F2(t, attach.Stream.(*task6BufferConn).Bytes(), wire.FlowResult{Status: wire.FlowStatusReject, Code: wire.FlowErrorCodePairTimeout})
}

func TestClaimRegistryTerminalRejectionConsumedOnce(t *testing.T) {
	registry := newClaimRegistry(time.Second, task6Limits(2))
	defer registry.Close()
	sessionID := wire.SessionID{5}
	registry.Reject(sessionID, 1, 1, ErrPairTimeout)
	meta := task6Metadata(wire.FlowKindTCP, wire.CarrierUDP, wire.CarrierTCP)
	first := task6Claim(sessionID, 1, 1, wire.FlowRoleAttach, wire.CarrierTCP, meta)
	if _, err := registry.Submit(context.Background(), first); !errors.Is(err, ErrPairTimeout) {
		t.Fatalf("first terminal consume = %v", err)
	}
	assertTask6F2(t, first.Stream.(*task6BufferConn).Bytes(), wire.FlowResult{Status: wire.FlowStatusReject, Code: wire.FlowErrorCodePairTimeout})
	second := task6Claim(sessionID, 1, 1, wire.FlowRoleAttach, wire.CarrierTCP, meta)
	if _, err := registry.Submit(context.Background(), second); !errors.Is(err, ErrPairTimeout) {
		t.Fatalf("second terminal consume = %v", err)
	}
	if got := second.Stream.(*task6BufferConn).Bytes(); len(got) != 0 {
		t.Fatalf("terminal rejection written twice: %x", got)
	}
}

func TestClaimRegistryQUICReplacementRejectsPendingAndCancelsActive(t *testing.T) {
	registry := newClaimRegistry(time.Second, task6Limits(4))
	defer registry.Close()
	sessionID := wire.SessionID{6}
	pending := task6Claim(sessionID, 1, 1, wire.FlowRoleAttach, wire.CarrierTCP,
		task6Metadata(wire.FlowKindTCP, wire.CarrierUDP, wire.CarrierTCP))
	pendingDone := make(chan error, 1)
	go func() {
		_, err := registry.Submit(context.Background(), pending)
		pendingDone <- err
	}()
	waitTask6Entries(t, registry, 1)
	duplex := task6Claim(sessionID, 2, 1, wire.FlowRoleDuplex, wire.CarrierUDP,
		task6Metadata(wire.FlowKindUDP, wire.CarrierUDP, wire.CarrierUDP))
	active, err := registry.Submit(context.Background(), duplex)
	if err != nil {
		t.Fatal(err)
	}
	registry.ReplaceSession(sessionID, 2, ErrClosed)
	if err := <-pendingDone; setupFailureCode(err) != wire.FlowErrorCodeSessionReplaced {
		t.Fatalf("pending replacement = %v", err)
	}
	assertTask6F2(t, pending.Stream.(*task6BufferConn).Bytes(), wire.FlowResult{Status: wire.FlowStatusReject, Code: wire.FlowErrorCodeSessionReplaced})
	select {
	case <-active.Context.Done():
	case <-time.After(time.Second):
		t.Fatal("active flow was not canceled by replacement")
	}
	assertTask6F2(t, duplex.Stream.(*task6BufferConn).Bytes(), wire.FlowResult{Status: wire.FlowStatusReject, Code: wire.FlowErrorCodeSessionReplaced})
}

func TestUDPPermitSharedAcrossQUICAndUOT(t *testing.T) {
	limits := task6Limits(1)
	registry := newClaimRegistry(time.Second, limits)
	defer registry.Close()
	sessionID := wire.SessionID{7}
	ctx, cancel := context.WithCancel(context.Background())
	first := task6Claim(sessionID, 1, 1, wire.FlowRoleOpen, wire.CarrierTCP,
		task6Metadata(wire.FlowKindUDP, wire.CarrierTCP, wire.CarrierUDP))
	firstDone := make(chan error, 1)
	go func() {
		_, err := registry.Submit(ctx, first)
		firstDone <- err
	}()
	waitTask6Entries(t, registry, 1)
	quic := task6Claim(sessionID, 2, 1, wire.FlowRoleDuplex, wire.CarrierUDP,
		task6Metadata(wire.FlowKindUDP, wire.CarrierUDP, wire.CarrierUDP))
	if _, err := registry.Submit(context.Background(), quic); setupFailureCode(err) != wire.FlowErrorCodeFlowLimit {
		t.Fatalf("cross-carrier UDP permit = %v", err)
	}
	cancel()
	<-firstDone
}

func TestUDPPermitReleasedOnPairTimeoutDialFailureCloseReplacement(t *testing.T) {
	t.Run("pair-timeout", func(t *testing.T) {
		registry := newClaimRegistry(15*time.Millisecond, task6Limits(1))
		defer registry.Close()
		pending := task6Claim(wire.SessionID{8}, 1, 1, wire.FlowRoleOpen, wire.CarrierTCP,
			task6Metadata(wire.FlowKindUDP, wire.CarrierTCP, wire.CarrierUDP))
		if _, err := registry.Submit(context.Background(), pending); !errors.Is(err, ErrPairTimeout) {
			t.Fatal(err)
		}
		assertTask6CanAcquireUDP(t, registry, wire.SessionID{8}, 2, 1)
	})
	for _, name := range []string{"dial-failure", "close"} {
		t.Run(name, func(t *testing.T) {
			registry := newClaimRegistry(time.Second, task6Limits(1))
			defer registry.Close()
			claim := task6Claim(wire.SessionID{9}, 1, 1, wire.FlowRoleDuplex, wire.CarrierTCP,
				task6Metadata(wire.FlowKindUDP, wire.CarrierTCP, wire.CarrierTCP))
			active, err := registry.Submit(context.Background(), claim)
			if err != nil {
				t.Fatal(err)
			}
			if name == "dial-failure" {
				_ = active.Readiness.Reject(errors.New("dial failed"))
			}
			active.Release()
			assertTask6CanAcquireUDP(t, registry, wire.SessionID{9}, 2, 1)
		})
	}
	t.Run("replacement", func(t *testing.T) {
		registry := newClaimRegistry(time.Second, task6Limits(1))
		defer registry.Close()
		claim := task6Claim(wire.SessionID{10}, 1, 1, wire.FlowRoleDuplex, wire.CarrierUDP,
			task6Metadata(wire.FlowKindUDP, wire.CarrierUDP, wire.CarrierUDP))
		if _, err := registry.Submit(context.Background(), claim); err != nil {
			t.Fatal(err)
		}
		registry.ReplaceSession(wire.SessionID{10}, 2, ErrClosed)
		assertTask6CanAcquireUDP(t, registry, wire.SessionID{10}, 2, 2)
	})
}

func TestReadyIsNotInferredFromHandleStreamReturn(t *testing.T) {
	writer := &task6BufferConn{}
	result := newSetupResult(writer, wire.FlowKindTCP, wire.CarrierTCP)
	readiness := newFlowReadiness(result.ready, result.reject)
	handler := newTask6Handler(t, task6Upstream{stream: func(context.Context, net.Conn, net.Addr, string, FlowReadiness) error {
		return nil
	}})
	ctx, cancel := context.WithCancel(context.Background())
	if err := handler.routeStream(ctx, &task6BufferConn{}, nil, "example.com:443", readiness, nil); err != nil {
		t.Fatal(err)
	}
	if got := writer.Bytes(); len(got) != 0 {
		t.Fatalf("HandleStream nil inferred readiness: %x", got)
	}
	cancel()
	waitTask6Bytes(t, writer, wire.FlowResultLen)
	assertTask6F2(t, writer.Bytes(), wire.FlowResult{Status: wire.FlowStatusReject, Code: wire.FlowErrorCodeSessionReplaced})
}

func TestReadyIsNotInferredFromHandlePacketReturn(t *testing.T) {
	writer := &task6BufferConn{}
	result := newSetupResult(writer, wire.FlowKindUDP, wire.CarrierTCP)
	readiness := newFlowReadiness(result.ready, result.reject)
	handler := newTask6Handler(t, task6Upstream{packet: func(context.Context, net.PacketConn, net.Addr, string, FlowReadiness) error {
		return nil
	}})
	ctx, cancel := context.WithCancel(context.Background())
	if err := handler.routePacket(ctx, newTask6PacketConn(), nil, "example.com:53", readiness, nil); err != nil {
		t.Fatal(err)
	}
	if got := writer.Bytes(); len(got) != 0 {
		t.Fatalf("HandlePacket nil inferred readiness: %x", got)
	}
	cancel()
	waitTask6Bytes(t, writer, 4)
	frame, err := wire.ReadUOTFrame(bytes.NewReader(writer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if frame.Kind != wire.UOTFrameReject || frame.Code != wire.FlowErrorCodeSessionReplaced {
		t.Fatalf("frame = %+v", frame)
	}
}

func TestDialUpstreamStreamReadyAfterDialSuccess(t *testing.T) {
	remote, remotePeer := net.Pipe()
	local, localPeer := net.Pipe()
	readiness := newTask6Readiness(nil)
	dialer := &task6Dialer{dial: func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "example.com:443" {
			t.Fatalf("dial = %s %s", network, address)
		}
		return remote, nil
	}}
	upstream := NewDialUpstream(dialer)
	done := make(chan error, 1)
	go func() { done <- upstream.HandleStream(context.Background(), local, nil, "example.com:443", readiness) }()
	readiness.waitReady(t)
	_ = localPeer.Close()
	_ = remotePeer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream relay did not stop")
	}
}

func TestDialUpstreamPacketReadyAfterConnectedUDPDial(t *testing.T) {
	remote, remotePeer := net.Pipe()
	packet := newTask6PacketConn()
	readiness := newTask6Readiness(nil)
	dialer := &task6Dialer{dial: func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "example.com:53" {
			t.Fatalf("dial = %s %s", network, address)
		}
		return remote, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- NewDialUpstream(dialer).HandlePacket(ctx, packet, nil, "example.com:53", readiness) }()
	readiness.waitReady(t)
	cancel()
	_ = remotePeer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("packet relay did not stop")
	}
}

func TestDialUpstreamDialFailureRejectsWithDialFailed(t *testing.T) {
	readiness := newTask6Readiness(nil)
	want := errors.New("dial failed")
	upstream := NewDialUpstream(&task6Dialer{dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, want
	}})
	if err := upstream.HandleStream(context.Background(), &task6BufferConn{}, nil, "example.com:443", readiness); !errors.Is(err, want) {
		t.Fatalf("HandleStream = %v", err)
	}
	if code := readiness.rejectCode(); code != wire.FlowErrorCodeDialFailed {
		t.Fatalf("reject code = %v, want dial_failed", code)
	}
}

func TestSetupResultBindsOnlySelectedDownlinkCarrier(t *testing.T) {
	meta := task6Metadata(wire.FlowKindTCP, wire.CarrierTCP, wire.CarrierUDP)
	uplink := task6Claim(wire.SessionID{11}, 1, 1, wire.FlowRoleOpen, wire.CarrierTCP, meta)
	if result := setupResultForClaim(uplink); result != nil {
		t.Fatal("uplink received setup result writer")
	}
	downlink := task6Claim(wire.SessionID{11}, 1, 1, wire.FlowRoleAttach, wire.CarrierUDP, meta)
	result := setupResultForClaim(downlink)
	if result == nil {
		t.Fatal("selected downlink did not receive setup result writer")
	}
	if err := result.ready(); err != nil {
		t.Fatal(err)
	}
	assertTask6F2(t, downlink.Stream.(*task6BufferConn).Bytes(), wire.FlowResult{Status: wire.FlowStatusReady})
}

func TestQUICUplinkControlNeverReceivesDownlinkResult(t *testing.T) {
	registry := newClaimRegistry(time.Second, task6Limits(2))
	defer registry.Close()
	meta := task6Metadata(wire.FlowKindUDP, wire.CarrierUDP, wire.CarrierTCP)
	quicOpen := task6Claim(wire.SessionID{12}, 1, 1, wire.FlowRoleOpen, wire.CarrierUDP, meta)
	quicOpen.Target = "example.com:53"
	openDone := make(chan error, 1)
	go func() {
		_, err := registry.Submit(context.Background(), quicOpen)
		openDone <- err
	}()
	waitTask6Entries(t, registry, 1)
	tcpAttach := task6Claim(wire.SessionID{12}, 1, 1, wire.FlowRoleAttach, wire.CarrierTCP, meta)
	active, err := registry.Submit(context.Background(), tcpAttach)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-openDone; err != nil {
		t.Fatal(err)
	}
	if err := active.Readiness.Ready(); err != nil {
		t.Fatal(err)
	}
	if got := quicOpen.Stream.(*task6BufferConn).Bytes(); len(got) != 0 {
		t.Fatalf("QUIC uplink received result: %x", got)
	}
	frame, err := wire.ReadUOTFrame(bytes.NewReader(tcpAttach.Stream.(*task6BufferConn).Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if frame.Kind != wire.UOTFrameReady {
		t.Fatalf("selected TCP frame = %+v", frame)
	}
	active.Release()
}

func TestReadyWriteFailureClosesRemoteAndStopsRelay(t *testing.T) {
	want := errors.New("ready write failed")
	remote, peer := net.Pipe()
	defer peer.Close()
	tracked := &task6CloseConn{Conn: remote}
	readiness := newTask6Readiness(want)
	upstream := NewDialUpstream(&task6Dialer{dial: func(context.Context, string, string) (net.Conn, error) {
		return tracked, nil
	}})
	if err := upstream.HandleStream(context.Background(), &task6BufferConn{}, nil, "example.com:443", readiness); !errors.Is(err, want) {
		t.Fatalf("HandleStream = %v, want %v", err, want)
	}
	if tracked.closed.Load() != 1 {
		t.Fatalf("remote close count = %d, want 1", tracked.closed.Load())
	}
}

func TestReadinessContextCancellationRejectsOnce(t *testing.T) {
	var rejects atomic.Int32
	var code atomic.Uint32
	readiness := newFlowReadiness(func() error { return nil }, func(value wire.FlowErrorCode) error {
		rejects.Add(1)
		code.Store(uint32(value))
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := readiness.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	_ = readiness.Reject(errors.New("second failure"))
	if rejects.Load() != 1 || wire.FlowErrorCode(code.Load()) != wire.FlowErrorCodeSessionReplaced {
		t.Fatalf("rejects = %d code = %v", rejects.Load(), wire.FlowErrorCode(code.Load()))
	}
}

func TestReadinessReplacementRejectsSessionReplaced(t *testing.T) {
	registry := newClaimRegistry(time.Second, task6Limits(1))
	defer registry.Close()
	claim := task6Claim(wire.SessionID{13}, 1, 1, wire.FlowRoleDuplex, wire.CarrierTCP,
		task6Metadata(wire.FlowKindTCP, wire.CarrierTCP, wire.CarrierTCP))
	active, err := registry.Submit(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	registry.ReplaceSession(wire.SessionID{13}, 2, ErrClosed)
	assertTask6F2(t, claim.Stream.(*task6BufferConn).Bytes(), wire.FlowResult{Status: wire.FlowStatusReject, Code: wire.FlowErrorCodeSessionReplaced})
	select {
	case <-active.Context.Done():
	case <-time.After(time.Second):
		t.Fatal("replacement did not cancel readiness context")
	}
}

type task6Upstream struct {
	stream func(context.Context, net.Conn, net.Addr, string, FlowReadiness) error
	packet func(context.Context, net.PacketConn, net.Addr, string, FlowReadiness) error
}

func (u task6Upstream) HandleStream(ctx context.Context, conn net.Conn, source net.Addr, target string, readiness FlowReadiness) error {
	if u.stream == nil {
		return nil
	}
	return u.stream(ctx, conn, source, target, readiness)
}

func (u task6Upstream) HandlePacket(ctx context.Context, conn net.PacketConn, source net.Addr, target string, readiness FlowReadiness) error {
	if u.packet == nil {
		return nil
	}
	return u.packet(ctx, conn, source, target, readiness)
}

func newTask6Handler(t *testing.T, upstream Upstream) *Handler {
	t.Helper()
	config, err := NewConfig(ConfigOptions{Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: upstream})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	return handler
}

func task6Limits(udp int) Limits {
	return Limits{
		PendingFlowsPerSession:          8,
		UDPFlowsPerSession:              udp,
		UDPQueueBytes:                   1024,
		UDPQueuePackets:                 4,
		ActiveQUICSessions:              4,
		AuthenticatedTCPIdleConnections: 8,
		MaxUnauthenticatedConnections:   8,
		MaxUnauthenticatedPerSource:     8,
		MaxConcurrentHandshakes:         4,
	}
}

func task6Metadata(kind wire.FlowKind, up, down wire.Carrier) claimMetadata {
	return claimMetadata{Kind: kind, Uplink: up, Downlink: down}
}

func task6Claim(sessionID wire.SessionID, flowID, generation uint64, role wire.FlowRole, carrier wire.Carrier, metadata claimMetadata) flowClaim {
	return flowClaim{
		SessionID:  sessionID,
		FlowID:     flowID,
		Generation: generation,
		Role:       role,
		Carrier:    carrier,
		Metadata:   metadata,
		Stream:     &task6BufferConn{},
	}
}

func waitTask6Entries(t *testing.T, registry *claimRegistry, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		registry.mu.Lock()
		got := len(registry.entries)
		registry.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("registry entries did not reach %d", want)
}

func assertTask6CanAcquireUDP(t *testing.T, registry *claimRegistry, sessionID wire.SessionID, flowID, generation uint64) {
	t.Helper()
	claim := task6Claim(sessionID, flowID, generation, wire.FlowRoleDuplex, wire.CarrierUDP,
		task6Metadata(wire.FlowKindUDP, wire.CarrierUDP, wire.CarrierUDP))
	active, err := registry.Submit(context.Background(), claim)
	if err != nil {
		t.Fatalf("UDP permit was not released: %v", err)
	}
	active.Release()
}

func assertTask6F2(t *testing.T, payload []byte, want wire.FlowResult) {
	t.Helper()
	reader := bytes.NewReader(payload)
	got, err := wire.ReadFlowResult(reader)
	if err != nil {
		t.Fatalf("ReadFlowResult(%x) = %v", payload, err)
	}
	if got != want || reader.Len() != 0 {
		t.Fatalf("FlowResult = %+v trailing=%d, want %+v", got, reader.Len(), want)
	}
}

func waitTask6Bytes(t *testing.T, conn *task6BufferConn, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(conn.Bytes()) >= count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("buffer did not reach %d bytes: %x", count, conn.Bytes())
}

type task6BufferConn struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	writeErr error
	closed   atomic.Int32
}

func (c *task6BufferConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *task6BufferConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buffer.Write(p)
}
func (c *task6BufferConn) Close() error                     { c.closed.Add(1); return nil }
func (c *task6BufferConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *task6BufferConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *task6BufferConn) SetDeadline(time.Time) error      { return nil }
func (c *task6BufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *task6BufferConn) SetWriteDeadline(time.Time) error { return nil }
func (c *task6BufferConn) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buffer.Bytes()...)
}

type task6PacketConn struct {
	closed chan struct{}
	once   sync.Once
}

func newTask6PacketConn() *task6PacketConn { return &task6PacketConn{closed: make(chan struct{})} }
func (c *task6PacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}
func (c *task6PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *task6PacketConn) Close() error                              { c.once.Do(func() { close(c.closed) }); return nil }
func (c *task6PacketConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (c *task6PacketConn) SetDeadline(time.Time) error               { return nil }
func (c *task6PacketConn) SetReadDeadline(time.Time) error           { return nil }
func (c *task6PacketConn) SetWriteDeadline(time.Time) error          { return nil }

type task6Dialer struct {
	dial func(context.Context, string, string) (net.Conn, error)
}

func (d *task6Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address)
}

type task6Readiness struct {
	readyOnce sync.Once
	readyCh   chan struct{}
	readyErr  error
	mu        sync.Mutex
	rejected  error
}

func newTask6Readiness(readyErr error) *task6Readiness {
	return &task6Readiness{readyCh: make(chan struct{}), readyErr: readyErr}
}

func (r *task6Readiness) Ready() error {
	r.readyOnce.Do(func() { close(r.readyCh) })
	return r.readyErr
}

func (r *task6Readiness) Reject(err error) error {
	r.mu.Lock()
	if r.rejected == nil {
		r.rejected = err
	}
	r.mu.Unlock()
	return nil
}

func (r *task6Readiness) waitReady(t *testing.T) {
	t.Helper()
	select {
	case <-r.readyCh:
	case <-time.After(time.Second):
		t.Fatal("readiness was not resolved")
	}
}

func (r *task6Readiness) rejectCode() wire.FlowErrorCode {
	r.mu.Lock()
	defer r.mu.Unlock()
	return setupFailureCode(r.rejected)
}

type task6CloseConn struct {
	net.Conn
	closed atomic.Int32
}

func (c *task6CloseConn) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}
