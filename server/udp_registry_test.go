package server

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

func TestSessionUDPQuotaIsSharedByCompactAndLegacy(t *testing.T) {
	routes := make(chan packetRoute, 1)
	session, _ := newUDPTestSession(t, Limits{QUICFlowsPerSession: 1}, routes)

	compact := newCompactUDPFlow(session, 1, "compact.example:53", wire.CarrierUDP)
	if !session.putFlow(compact.flowID, compact) {
		t.Fatal("compact flow did not reserve the session quota")
	}
	legacy := newLegacyUDPFlow(session, legacyUDPKey{flowID: 2, target: "legacy.example:53"})
	if session.reserveLegacyFlow(legacy) {
		t.Fatal("legacy flow exceeded quota already held by Compact")
	}
	legacy.shutdown(net.ErrClosed)

	compact.shutdown(net.ErrClosed)
	legacy = newLegacyUDPFlow(session, legacyUDPKey{flowID: 2, target: "legacy.example:53"})
	if !session.reserveLegacyFlow(legacy) {
		t.Fatal("legacy flow did not reserve quota released by Compact")
	}
	secondCompact := newCompactUDPFlow(session, 3, "second-compact.example:53", wire.CarrierUDP)
	if session.putFlow(secondCompact.flowID, secondCompact) {
		t.Fatal("Compact flow exceeded quota already held by legacy")
	}
	secondCompact.shutdown(net.ErrClosed)

	legacy.shutdown(net.ErrClosed)
	if active := sessionUDPActiveFlows(session); active != 0 {
		t.Fatalf("active UDP flows = %d, want 0", active)
	}
}

func TestUDPFlowIdleStartsOnlyAfterRegistryPublication(t *testing.T) {
	t.Run("compact", func(t *testing.T) {
		routes := make(chan packetRoute, 1)
		session, _ := newUDPTestSession(t, Limits{}, routes)
		flow := newCompactUDPFlow(session, 11, "compact-order.example:53", wire.CarrierUDP)
		if flow.generation != 0 || compactIdleStarted(flow) {
			t.Fatalf("constructed Compact flow generation=%d idle_started=%v", flow.generation, compactIdleStarted(flow))
		}

		flow.mu.Lock()
		locked := true
		defer func() {
			if locked {
				flow.mu.Unlock()
			}
		}()
		reserved := make(chan bool, 1)
		go func() { reserved <- session.putFlow(flow.flowID, flow) }()
		entry := waitForCompactEntry(t, session, flow.flowID)
		if entry.symmetric != flow || entry.generation == 0 || flow.generation != entry.generation {
			t.Fatalf("published Compact entry=%+v flow_generation=%d", entry, flow.generation)
		}
		if flow.idle != nil {
			t.Fatal("Compact idle timer started before reservation returned")
		}
		flow.mu.Unlock()
		locked = false
		if !<-reserved {
			t.Fatal("Compact reservation failed")
		}
		if !compactIdleStarted(flow) {
			t.Fatal("Compact idle timer did not start after publication")
		}
		flow.shutdown(net.ErrClosed)
	})

	t.Run("legacy", func(t *testing.T) {
		routes := make(chan packetRoute, 1)
		session, _ := newUDPTestSession(t, Limits{}, routes)
		flow := newLegacyUDPFlow(session, legacyUDPKey{flowID: 12, target: "legacy-order.example:53"})
		if legacyIdleStarted(flow) {
			t.Fatal("constructed legacy flow already has an idle timer")
		}

		flow.mu.Lock()
		locked := true
		defer func() {
			if locked {
				flow.mu.Unlock()
			}
		}()
		reserved := make(chan bool, 1)
		go func() { reserved <- session.reserveLegacyFlow(flow) }()
		waitForLegacyEntry(t, session, flow.key, flow)
		if flow.idle != nil {
			t.Fatal("legacy idle timer started before reservation returned")
		}
		flow.mu.Unlock()
		locked = false
		if !<-reserved {
			t.Fatal("legacy reservation failed")
		}
		if !legacyIdleStarted(flow) {
			t.Fatal("legacy idle timer did not start after publication")
		}
		flow.shutdown(net.ErrClosed)
	})
}

func TestUDPReservationFailureDoesNotStartIdleOrLeakQuota(t *testing.T) {
	routes := make(chan packetRoute, 1)
	session, _ := newUDPTestSession(t, Limits{QUICFlowsPerSession: 1}, routes)

	compact := newCompactUDPFlow(session, 21, "compact-holder.example:53", wire.CarrierUDP)
	if !session.putFlow(compact.flowID, compact) {
		t.Fatal("Compact holder reservation failed")
	}
	legacyRejected := newLegacyUDPFlow(session, legacyUDPKey{flowID: 22, target: "legacy-rejected.example:53"})
	if session.reserveLegacyFlow(legacyRejected) {
		t.Fatal("legacy reservation unexpectedly succeeded")
	}
	if legacyIdleStarted(legacyRejected) {
		t.Fatal("rejected legacy flow started an idle timer")
	}
	legacyRejected.shutdown(net.ErrClosed)
	legacyRejected.shutdown(net.ErrClosed)
	if active := sessionUDPActiveFlows(session); active != 1 {
		t.Fatalf("active flows after rejected legacy shutdown = %d, want 1", active)
	}
	compact.shutdown(net.ErrClosed)

	legacy := newLegacyUDPFlow(session, legacyUDPKey{flowID: 23, target: "legacy-holder.example:53"})
	if !session.reserveLegacyFlow(legacy) {
		t.Fatal("legacy holder reservation failed")
	}
	compactRejected := newCompactUDPFlow(session, 24, "compact-rejected.example:53", wire.CarrierUDP)
	if session.putFlow(compactRejected.flowID, compactRejected) {
		t.Fatal("Compact reservation unexpectedly succeeded")
	}
	if compactRejected.generation != 0 || compactIdleStarted(compactRejected) {
		t.Fatalf("rejected Compact generation=%d idle_started=%v", compactRejected.generation, compactIdleStarted(compactRejected))
	}
	compactRejected.shutdown(net.ErrClosed)
	compactRejected.shutdown(net.ErrClosed)
	if active := sessionUDPActiveFlows(session); active != 1 {
		t.Fatalf("active flows after rejected Compact shutdown = %d, want 1", active)
	}
	legacy.shutdown(net.ErrClosed)
	if active := sessionUDPActiveFlows(session); active != 0 {
		t.Fatalf("active flows after holder shutdown = %d, want 0", active)
	}
}

func TestUDPShutdownIsIdempotentAndReleasesQuotaOnce(t *testing.T) {
	routes := make(chan packetRoute, 1)
	session, _ := newUDPTestSession(t, Limits{QUICFlowsPerSession: 2}, routes)
	compact := newCompactUDPFlow(session, 31, "compact-shutdown.example:53", wire.CarrierUDP)
	legacy := newLegacyUDPFlow(session, legacyUDPKey{flowID: 32, target: "legacy-shutdown.example:53"})
	if !session.putFlow(compact.flowID, compact) || !session.reserveLegacyFlow(legacy) {
		t.Fatal("flow reservation failed")
	}
	if active := sessionUDPActiveFlows(session); active != 2 {
		t.Fatalf("active flows before shutdown = %d, want 2", active)
	}

	compact.shutdown(net.ErrClosed)
	compact.shutdown(net.ErrClosed)
	if active := sessionUDPActiveFlows(session); active != 1 {
		t.Fatalf("active flows after repeated Compact shutdown = %d, want 1", active)
	}
	legacy.shutdown(net.ErrClosed)
	legacy.shutdown(net.ErrClosed)
	if active := sessionUDPActiveFlows(session); active != 0 {
		t.Fatalf("active flows after repeated legacy shutdown = %d, want 0", active)
	}
}

func TestCompactOldShutdownDoesNotDetachReusedFlowID(t *testing.T) {
	routes := make(chan packetRoute, 1)
	session, _ := newUDPTestSession(t, Limits{QUICFlowsPerSession: 1}, routes)
	oldFlow := newCompactUDPFlow(session, 41, "old.example:53", wire.CarrierUDP)
	if !session.putFlow(oldFlow.flowID, oldFlow) {
		t.Fatal("old Compact reservation failed")
	}
	oldGeneration := oldFlow.generation
	stopCompactIdle(oldFlow)
	if _, ok := session.detachCompactEntry(oldFlow.flowID, oldGeneration); !ok {
		t.Fatal("old Compact detach failed")
	}

	newFlow := newCompactUDPFlow(session, oldFlow.flowID, "new.example:53", wire.CarrierUDP)
	if !session.putFlow(newFlow.flowID, newFlow) {
		t.Fatal("reused Compact reservation failed")
	}
	if newFlow.generation == 0 || newFlow.generation == oldGeneration {
		t.Fatalf("new generation = %d, old = %d", newFlow.generation, oldGeneration)
	}

	oldFlow.shutdown(net.ErrClosed)
	oldFlow.shutdown(net.ErrClosed)
	if entry := session.getCompactEntry(newFlow.flowID); entry == nil || entry.symmetric != newFlow {
		t.Fatalf("old shutdown removed reused entry: %+v", entry)
	}
	if active := sessionUDPActiveFlows(session); active != 1 {
		t.Fatalf("active flows after stale shutdown = %d, want 1", active)
	}
	newFlow.shutdown(net.ErrClosed)
}

func waitForCompactEntry(t *testing.T, session *portalSession, flowID uint64) *compactUDPEntry {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		session.mu.Lock()
		entry := session.udp.compact[flowID]
		session.mu.Unlock()
		if entry != nil {
			return entry
		}
		runtime.Gosched()
	}
	t.Fatal("Compact entry was not published")
	return nil
}

func waitForLegacyEntry(t *testing.T, session *portalSession, key legacyUDPKey, flow *legacyUDPFlow) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		session.mu.Lock()
		current := session.udp.legacy[key]
		session.mu.Unlock()
		if current == flow {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("legacy entry was not published")
}

func sessionUDPActiveFlows(session *portalSession) int {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.udp.activeFlows
}

func compactIdleStarted(flow *compactUDPFlow) bool {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	return flow.idle != nil
}

func legacyIdleStarted(flow *legacyUDPFlow) bool {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	return flow.idle != nil
}

func stopCompactIdle(flow *compactUDPFlow) {
	flow.mu.Lock()
	if flow.idle != nil {
		flow.idle.Stop()
		flow.idle = nil
	}
	flow.mu.Unlock()
}
