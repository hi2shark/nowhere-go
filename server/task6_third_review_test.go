package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/hi2shark/nowhere-go/wire"
)

func TestQUICReconnectDoesNotAdoptLingeringPhysicalGeneration(t *testing.T) {
	var upstreamCalls atomic.Int32
	handler, config := newTask6RereviewHandler(t, upstreamFuncs{
		stream: func(_ context.Context, _ net.Conn, _ net.Addr, _ string, readiness FlowReadiness) error {
			upstreamCalls.Add(1)
			return readiness.Ready()
		},
	}, Timeouts{}, nil)
	sessionID := wire.SessionID{0xb1}
	oldSession := registerTask6Session(t, handler, sessionID)
	oldGeneration := oldSession.Generation

	lingering, err := handler.claims.Submit(context.Background(), flowClaim{
		SessionID: sessionID, FlowID: 1, Generation: oldGeneration, BoundGeneration: true,
		Role: wire.FlowRoleDuplex, Carrier: wire.CarrierUDP,
		Metadata: claimMetadata{Kind: wire.FlowKindTCP, Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP},
		Stream:   &task6BufferConn{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lingering.Release()

	oldSession.Close()
	handler.sessions.Unregister(oldSession)
	newSession := registerTask6Session(t, handler, sessionID)

	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 2, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}
	setup, err := wire.EncodeFlowSetup(header, "example.com:443", config.EffectiveSpec())
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
		t.Fatalf("reconnect adopted lingering physical generation %d", oldGeneration)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("old delayed claim reached upstream %d times", got)
	}
}

func TestClaimRegistryRejectsZeroBoundGeneration(t *testing.T) {
	t.Run("submit", func(t *testing.T) {
		handler := newTask6Handler(t, noopUpstream{})
		sessionID := wire.SessionID{0xb2}
		registerTask6Session(t, handler, sessionID)
		stream := &task6BufferConn{}
		claim := flowClaim{
			SessionID: sessionID, FlowID: 1, BoundGeneration: true,
			Role: wire.FlowRoleDuplex, Carrier: wire.CarrierUDP,
			Metadata: claimMetadata{Kind: wire.FlowKindTCP, Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP},
			Stream:   stream,
		}
		active, err := handler.claims.Submit(context.Background(), claim)
		if active != nil {
			active.Release()
		}
		if setupFailureCode(err) != wire.FlowErrorCodeMetadataConflict {
			t.Fatalf("zero bound Submit = %v (%v), want metadata_conflict", err, setupFailureCode(err))
		}
		assertTask6F2(t, stream.Bytes(), wire.FlowResult{
			Status: wire.FlowStatusReject,
			Code:   wire.FlowErrorCodeMetadataConflict,
		})
	})

	t.Run("reject-claim", func(t *testing.T) {
		handler := newTask6Handler(t, noopUpstream{})
		sessionID := wire.SessionID{0xb3}
		registerTask6Session(t, handler, sessionID)
		stream := &task6BufferConn{}
		claim := flowClaim{
			SessionID: sessionID, FlowID: 1, BoundGeneration: true,
			Role: wire.FlowRoleDuplex, Carrier: wire.CarrierUDP,
			Metadata: claimMetadata{Kind: wire.FlowKindTCP, Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP},
			Stream:   stream,
		}
		handler.claims.RejectClaim(claim, &wire.FlowError{Code: wire.FlowErrorCodeInvalidRequest})
		assertTask6F2(t, stream.Bytes(), wire.FlowResult{
			Status: wire.FlowStatusReject,
			Code:   wire.FlowErrorCodeMetadataConflict,
		})
		handler.claims.mu.Lock()
		entry := handler.claims.entries[claimKey{sessionID: sessionID, flowID: claim.FlowID}]
		handler.claims.mu.Unlock()
		if entry != nil {
			t.Fatal("zero bound RejectClaim created terminal state")
		}
	})
}

func TestSessionManagerWithoutRegistryLatchesGenerationExhaustion(t *testing.T) {
	manager := newSessionManager()
	manager.nextGeneration = ^uint64(0)
	first := newPortalSession(wire.SessionID{0xb4}, &fakeQuicConn{}, nil, nil)
	if err := manager.Register(first); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("first exhausted Register = %v, want ErrSessionLimit", err)
	}
	second := newPortalSession(wire.SessionID{0xb5}, &fakeQuicConn{}, nil, nil)
	if err := manager.Register(second); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("second exhausted Register = %v, want latched ErrSessionLimit", err)
	}
	if second.Generation != 0 {
		t.Fatalf("exhausted manager reused generation %d", second.Generation)
	}
	if current := manager.Current(second.ID); current != nil {
		t.Fatalf("exhausted manager registered session %+v", current)
	}
}
