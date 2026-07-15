package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/diagnostic"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestClaimRegistryBudgetRejectCleansProvisionalGeneration(t *testing.T) {
	limits := task6Limits(1)
	limits.AuthenticatedTCPIdleConnections = 1
	registry := newClaimRegistry(time.Second, limits)
	defer registry.Close()

	pairWait := make(chan struct{}, 1)
	registry.setObserver(diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
		if event.Code == "pair_wait" {
			select {
			case pairWait <- struct{}{}:
			default:
			}
		}
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	filler := task6Claim(wire.SessionID{0xc0}, 1, 0, wire.FlowRoleOpen, wire.CarrierTCP,
		task6Metadata(wire.FlowKindTCP, wire.CarrierTCP, wire.CarrierUDP))
	fillerDone := make(chan error, 1)
	go func() {
		_, err := registry.Submit(ctx, filler)
		fillerDone <- err
	}()
	waitTask6FinalPairWait(t, pairWait)

	for i := 0; i < 32; i++ {
		sessionID := wire.SessionID{0xc1, byte(i + 1)}
		claim := task6Claim(sessionID, 1, 0, wire.FlowRoleOpen, wire.CarrierTCP,
			task6Metadata(wire.FlowKindTCP, wire.CarrierTCP, wire.CarrierUDP))
		if _, err := registry.Submit(context.Background(), claim); !errors.Is(err, ErrPairLimit) {
			t.Fatalf("budget reject %d = %v, want ErrPairLimit", i, err)
		}

		registry.mu.Lock()
		_, generationRetained := registry.generations[sessionID]
		provenanceRetained := false
		for key := range registry.provenance {
			if key.sessionID == sessionID {
				provenanceRetained = true
				break
			}
		}
		entry := registry.entries[claimKey{sessionID: sessionID, flowID: claim.FlowID}]
		registry.mu.Unlock()
		if generationRetained || provenanceRetained || entry != nil {
			t.Fatalf("budget reject %d retained generation=%v provenance=%v entry=%v", i, generationRetained, provenanceRetained, entry != nil)
		}
	}

	registry.mu.Lock()
	generations := len(registry.generations)
	provenance := len(registry.provenance)
	entries := len(registry.entries)
	idleTCP := registry.idleTCP
	registry.mu.Unlock()
	if generations != 1 || provenance != 1 || entries != 1 || idleTCP != 1 {
		t.Fatalf("budget-full registry state generations=%d provenance=%d entries=%d idleTCP=%d, want 1/1/1/1", generations, provenance, entries, idleTCP)
	}

	cancel()
	select {
	case err := <-fillerDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("filler Submit = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("filler Submit did not stop after cancellation")
	}
}

func TestClaimRegistryCloseClearsLifecycleState(t *testing.T) {
	limits := task6Limits(2)
	registry := newClaimRegistry(time.Second, limits)
	defer registry.Close()

	terminalSession := wire.SessionID{0xd0}
	registry.Reject(terminalSession, 1, 0, ErrPairTimeout)

	physicalSession := wire.SessionID{0xd1}
	generation, cleanup := registry.beginSessionRegistration(physicalSession, false, ErrClosed)
	cleanup.run()
	activeClaim := task6Claim(physicalSession, 1, generation, wire.FlowRoleDuplex, wire.CarrierUDP,
		task6Metadata(wire.FlowKindUDP, wire.CarrierUDP, wire.CarrierUDP))
	activeClaim.BoundGeneration = true
	active, err := registry.Submit(context.Background(), activeClaim)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Release()

	pairWait := make(chan struct{}, 1)
	registry.setObserver(diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
		if event.Code == "pair_wait" {
			select {
			case pairWait <- struct{}{}:
			default:
			}
		}
	}))
	pendingClaim := task6Claim(wire.SessionID{0xd2}, 1, 0, wire.FlowRoleOpen, wire.CarrierTCP,
		task6Metadata(wire.FlowKindTCP, wire.CarrierTCP, wire.CarrierUDP))
	pendingDone := make(chan error, 1)
	go func() {
		_, err := registry.Submit(context.Background(), pendingClaim)
		pendingDone <- err
	}()
	waitTask6FinalPairWait(t, pairWait)

	registry.mu.Lock()
	before := [8]int{
		len(registry.entries), len(registry.terminalOrder), len(registry.generations), len(registry.registered),
		len(registry.provenance), len(registry.pending), len(registry.udpInUse), registry.idleTCP,
	}
	registry.mu.Unlock()
	for i, value := range before {
		if value == 0 {
			t.Fatalf("lifecycle state %d was not populated before Close: %v", i, before)
		}
	}

	registry.Close()
	select {
	case err := <-pendingDone:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("pending Submit after Close = %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending Submit did not stop after Close")
	}

	registry.mu.Lock()
	after := [9]int{
		len(registry.entries), len(registry.terminalOrder), len(registry.generations), len(registry.registered),
		len(registry.provenance), len(registry.pending), len(registry.udpInUse), registry.idleTCP, int(registry.nextGeneration),
	}
	registry.mu.Unlock()
	if after != [9]int{} {
		t.Fatalf("lifecycle state retained after Close: %v", after)
	}
}

func waitTask6FinalPairWait(t *testing.T, pairWait <-chan struct{}) {
	t.Helper()
	select {
	case <-pairWait:
	case <-time.After(time.Second):
		t.Fatal("pair_wait event not observed")
	}
}
