package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

func TestQUICDelayedOldStreamCannotClaimReplacementGeneration(t *testing.T) {
	config, err := NewConfig(ConfigOptions{Password: "secret", Timeouts: Timeouts{FlowPair: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	var upstreamCalls atomic.Int32
	handler, err := NewHandler(HandlerOptions{
		Config: config,
		Upstream: upstreamFuncs{stream: func(_ context.Context, _ net.Conn, _ net.Addr, _ string, readiness FlowReadiness) error {
			upstreamCalls.Add(1)
			return readiness.Ready()
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	sessionID := wire.SessionID{0x61}
	oldSession := newPortalSession(sessionID, &fakeQuicConn{}, handler, &net.UDPAddr{})
	newSession := newPortalSession(sessionID, &fakeQuicConn{}, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(oldSession); err != nil {
		t.Fatal(err)
	}
	if err := handler.sessions.Register(newSession); err != nil {
		t.Fatal(err)
	}

	header := wire.FlowHeader{
		Role: wire.FlowRoleOpen, FlowID: 1, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	}
	client, tcpDone := startTCPFlow(t, handler, config, sessionID, header, "example.com:443")
	defer client.Close()
	waitTask6Entries(t, handler.claims, 1)

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
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("old generation reached upstream %d times", got)
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

func TestSessionManagerConcurrentSameIDAllocatesDistinctGenerations(t *testing.T) {
	handler := newTask6Handler(t, noopUpstream{})
	sessionID := wire.SessionID{0x62}
	sessions := []*portalSession{
		newPortalSession(sessionID, &fakeQuicConn{}, handler, &net.UDPAddr{}),
		newPortalSession(sessionID, &fakeQuicConn{}, handler, &net.UDPAddr{}),
	}

	start := make(chan struct{})
	errs := make(chan error, len(sessions))
	var wg sync.WaitGroup
	for _, session := range sessions {
		wg.Add(1)
		go func(session *portalSession) {
			defer wg.Done()
			<-start
			errs <- handler.sessions.Register(session)
		}(session)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	generations := []int{int(sessions[0].Generation), int(sessions[1].Generation)}
	sort.Ints(generations)
	if generations[0] != 1 || generations[1] != 2 {
		t.Fatalf("generations = %v, want [1 2]", generations)
	}
	current := handler.sessions.Current(sessionID)
	if current == nil || current.Generation != 2 {
		t.Fatalf("current session = %+v, want generation 2", current)
	}
	closed := sessions[0].Conn.(*fakeQuicConn).closed.Load() + sessions[1].Conn.(*fakeQuicConn).closed.Load()
	if closed != 1 {
		t.Fatalf("replaced physical connection close count = %d, want 1", closed)
	}
}

func TestClaimRegistryTerminalStateIsBounded(t *testing.T) {
	limits := task6Limits(2)
	limits.PendingFlowsPerSession = 4
	registry := newClaimRegistry(time.Second, limits)
	defer registry.Close()

	for i := 0; i < 64; i++ {
		sessionID := wire.SessionID{byte(i + 1), 0x63}
		generation := registry.CurrentGeneration(sessionID)
		registry.Reject(sessionID, 1, generation, ErrPairTimeout)
	}

	registry.mu.Lock()
	entries := len(registry.entries)
	generations := len(registry.generations)
	registry.mu.Unlock()
	if entries > limits.PendingFlowsPerSession {
		t.Fatalf("terminal entries = %d, want <= %d", entries, limits.PendingFlowsPerSession)
	}
	if generations > limits.PendingFlowsPerSession {
		t.Fatalf("generation records = %d, want <= %d", generations, limits.PendingFlowsPerSession)
	}
}

func TestClaimRegistryGenerationReclaimedAfterLastLiveState(t *testing.T) {
	registry := newClaimRegistry(time.Second, task6Limits(2))
	defer registry.Close()
	sessionID := wire.SessionID{0x64}
	generation := registry.CurrentGeneration(sessionID)
	claim := task6Claim(sessionID, 1, generation, wire.FlowRoleDuplex, wire.CarrierTCP,
		task6Metadata(wire.FlowKindTCP, wire.CarrierTCP, wire.CarrierTCP))
	active, err := registry.Submit(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	active.Release()

	registry.mu.Lock()
	_, retained := registry.generations[sessionID]
	registry.mu.Unlock()
	if retained {
		t.Fatal("generation record retained after last live claim")
	}
}

func TestClaimRegistryLateSelectedTimeoutAndSingleConsumptionSurviveBoundedLifecycle(t *testing.T) {
	limits := task6Limits(2)
	limits.PendingFlowsPerSession = 2
	registry := newClaimRegistry(20*time.Millisecond, limits)
	defer registry.Close()
	sessionID := wire.SessionID{0x65}
	meta := task6Metadata(wire.FlowKindTCP, wire.CarrierTCP, wire.CarrierUDP)
	open := task6Claim(sessionID, 1, 1, wire.FlowRoleOpen, wire.CarrierTCP, meta)
	if _, err := registry.Submit(context.Background(), open); !errors.Is(err, ErrPairTimeout) {
		t.Fatalf("open = %v, want pair timeout", err)
	}

	attach := task6Claim(sessionID, 1, 1, wire.FlowRoleAttach, wire.CarrierUDP, meta)
	if _, err := registry.Submit(context.Background(), attach); !errors.Is(err, ErrPairTimeout) {
		t.Fatalf("late selected attach = %v, want original pair timeout", err)
	}
	assertTask6F2(t, attach.Stream.(*task6BufferConn).Bytes(), wire.FlowResult{
		Status: wire.FlowStatusReject,
		Code:   wire.FlowErrorCodePairTimeout,
	})

	duplicate := task6Claim(sessionID, 1, 1, wire.FlowRoleAttach, wire.CarrierUDP, meta)
	if _, err := registry.Submit(context.Background(), duplicate); !errors.Is(err, ErrPairTimeout) {
		t.Fatalf("duplicate terminal consume = %v, want original pair timeout", err)
	}
	if payload := duplicate.Stream.(*task6BufferConn).Bytes(); len(payload) != 0 {
		t.Fatalf("terminal rejection written more than once: %x", payload)
	}
}
