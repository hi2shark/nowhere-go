package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

func TestServeQUICRejectsLegacyDerivedUDP(t *testing.T) {
	// v1.3 derived-order UDP request for spec=auto. Its field order is
	// version, type, target, flow ID, followed by the payload. It deliberately
	// has no v1.4 FLOW setup envelope or NOWU magic.
	legacyFrame := []byte{
		0x01, 0x01,
		0x00, 0x11,
		0x6c, 0x65, 0x67, 0x61, 0x63, 0x79, 0x2e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x3a, 0x35, 0x33,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x6c, 0x65, 0x67, 0x61, 0x63, 0x79,
	}
	testLegacyQUICDatagramRejected(t, wire.SessionID{0x14}, 0x0102030405060708, legacyFrame)
}

func TestServeQUICRejectsLegacyCompactUDP(t *testing.T) {
	const flowID = uint64(0x1112131415161718)
	target := []byte("legacy.invalid:53")
	legacyFrame := []byte{0x01, 0x11}
	var encodedFlowID [8]byte
	binary.BigEndian.PutUint64(encodedFlowID[:], flowID)
	legacyFrame = append(legacyFrame, encodedFlowID[:]...)
	legacyFrame = append(legacyFrame, byte(wire.CarrierUDP), byte(len(target)>>8), byte(len(target)))
	legacyFrame = append(legacyFrame, target...)
	legacyFrame = append(legacyFrame, "legacy"...)
	testLegacyQUICDatagramRejected(t, wire.SessionID{0x16}, flowID, legacyFrame)
}

func TestServeTCPRejectsLegacyUOT(t *testing.T) {
	request, err := wire.EncodeTCPRequest("uot.nowhere.invalid:0", mustLegacyConfig(t).EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	target := []byte("legacy.invalid:53")
	legacy := append(request, byte(len(target)>>8), byte(len(target)))
	legacy = append(legacy, target...)
	legacy = append(legacy, 0, 6)
	legacy = append(legacy, "legacy"...)
	testLegacyTCPSetupRejected(t, wire.SessionID{0x17}, legacy, wire.FlowKindUDP)
}

func TestServeTCPRejectsMissingFlowEnvelope(t *testing.T) {
	config := mustLegacyConfig(t)
	legacy, err := wire.EncodeTCPRequest("legacy.invalid:443", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	testLegacyTCPSetupRejected(t, wire.SessionID{0x18}, legacy, wire.FlowKindTCP)
}

func testLegacyQUICDatagramRejected(t *testing.T, sessionID wire.SessionID, flowID uint64, legacyFrame []byte) {
	t.Helper()
	var upstreamCalls atomic.Int32
	handler := newLegacyRejectionHandler(t, &upstreamCalls)
	ctx := context.Background()
	session := newPortalSession(sessionID, &fakeQuicConn{}, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(session); err != nil {
		t.Fatal(err)
	}

	session.handleDatagram(ctx, legacyFrame)
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls after legacy frame = %d, want 0", got)
	}
	assertLegacyStateClean(t, session, handler)

	// Reusing the rejected flow ID under a one-flow limit proves that the
	// legacy frame did not create a flow or retain its permit/budget.
	runValidQUICUDPFlow(t, ctx, session, flowID)
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls after valid 1.4 flow = %d, want 1", got)
	}
	assertLegacyStateClean(t, session, handler)
}

func testLegacyTCPSetupRejected(t *testing.T, sessionID wire.SessionID, legacySetup []byte, validKind wire.FlowKind) {
	t.Helper()
	var upstreamCalls atomic.Int32
	handler := newLegacyRejectionHandler(t, &upstreamCalls)
	session := newPortalSession(sessionID, &fakeQuicConn{}, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(session); err != nil {
		t.Fatal(err)
	}

	serverConn, clientConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- handler.HandleConn(context.Background(), serverConn, &net.TCPAddr{}, nil)
	}()
	auth, err := wire.MakeAuthFrameWithSession("secret", handler.config.spec, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = clientConn.Write(append(auth, legacySetup...))
		_ = clientConn.Close()
	}()
	if err := <-done; !errors.Is(err, wire.ErrInvalidFlowHeader) {
		t.Fatalf("legacy HandleConn error = %v, want ErrInvalidFlowHeader", err)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls after legacy setup = %d, want 0", got)
	}
	assertLegacyStateClean(t, session, handler)

	flowID := uint64(0x2021222324252627)
	if validKind == wire.FlowKindUDP {
		runValidTCPUDPFlow(t, handler, sessionID, flowID)
	} else {
		runValidTCPTCPFlow(t, handler, sessionID, flowID)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls after valid 1.4 flow = %d, want 1", got)
	}
	assertLegacyStateClean(t, session, handler)
}

func mustLegacyConfig(t *testing.T) *Config {
	t.Helper()
	config, err := NewConfig(ConfigOptions{Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func newLegacyRejectionHandler(t *testing.T, calls *atomic.Int32) *Handler {
	t.Helper()
	config, err := NewConfig(ConfigOptions{
		Password: "secret",
		Limits: Limits{
			PendingFlowsPerSession: 1,
			UDPFlowsPerSession:     1,
			UDPQueueBytes:          64,
			UDPQueuePackets:        1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{
		Config: config,
		Upstream: upstreamFuncs{
			stream: func(_ context.Context, conn net.Conn, _ net.Addr, target string, readiness FlowReadiness) error {
				calls.Add(1)
				if target != "example.com:443" {
					t.Fatalf("TCP target = %q", target)
				}
				if err := readiness.Ready(); err != nil {
					return err
				}
				return conn.Close()
			},
			packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, target string, readiness FlowReadiness) error {
				calls.Add(1)
				if target != "example.com:53" {
					t.Fatalf("UDP target = %q", target)
				}
				if err := readiness.Ready(); err != nil {
					return err
				}
				return pc.Close()
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	return handler
}

func runValidQUICUDPFlow(t *testing.T, ctx context.Context, session *portalSession, flowID uint64) {
	t.Helper()
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: flowID, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}
	setup, err := wire.EncodeFlowSetup(header, "example.com:53", session.Handler.config.spec)
	if err != nil {
		t.Fatal(err)
	}
	stream := newRecordingQuicStream(setup)
	session.handleStream(ctx, stream)
	assertFlowResult(t, bytes.NewReader(stream.writtenBytes()), wire.FlowResult{Status: wire.FlowStatusReady})
}

func runValidTCPTCPFlow(t *testing.T, handler *Handler, sessionID wire.SessionID, flowID uint64) {
	t.Helper()
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: flowID, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	}
	client, done := startTCPFlow(t, handler, handler.config, sessionID, header, "example.com:443")
	defer client.Close()
	assertFlowResult(t, client, wire.FlowResult{Status: wire.FlowStatusReady})
	if err := <-done; err != nil {
		t.Fatalf("valid TCP HandleConn = %v", err)
	}
}

func runValidTCPUDPFlow(t *testing.T, handler *Handler, sessionID wire.SessionID, flowID uint64) {
	t.Helper()
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: flowID, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	}
	client, done := startTCPFlow(t, handler, handler.config, sessionID, header, "example.com:53")
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := wire.ReadUOTFrame(client)
	if err != nil {
		t.Fatalf("valid ReadUOTFrame = %v", err)
	}
	if frame.Kind != wire.UOTFrameReady {
		t.Fatalf("valid UoT frame = %+v, want READY", frame)
	}
	if err := <-done; err != nil {
		t.Fatalf("valid UDP HandleConn = %v", err)
	}
}

func assertLegacyStateClean(t *testing.T, session *portalSession, handler *Handler) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		session.mu.Lock()
		flows := len(session.flows)
		pendingControls := len(session.pendingControls)
		queuedBytes := session.queuedBytes
		pendingBytes := session.pendingBytes
		session.mu.Unlock()
		session.budget.mu.Lock()
		budgetUsed := session.budget.used
		session.budget.mu.Unlock()

		handler.claims.mu.Lock()
		pendingClaims := len(handler.claims.pending)
		entries := len(handler.claims.entries)
		permits := 0
		for _, count := range handler.claims.udpInUse {
			permits += count
		}
		idleTCP := handler.claims.idleTCP
		handler.claims.mu.Unlock()

		handler.tasks.mu.Lock()
		tasks := len(handler.tasks.tasks)
		detached := len(handler.tasks.detached)
		handler.tasks.mu.Unlock()

		if flows == 0 && pendingControls == 0 && queuedBytes == 0 && pendingBytes == 0 && budgetUsed == 0 &&
			pendingClaims == 0 && entries == 0 && permits == 0 && idleTCP == 0 && tasks == 0 && detached == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("legacy state leaked: flows=%d pending_controls=%d queued=%d pending_bytes=%d budget=%d pending_claims=%d entries=%d permits=%d idle_tcp=%d tasks=%d detached=%d",
				flows, pendingControls, queuedBytes, pendingBytes, budgetUsed, pendingClaims, entries, permits, idleTCP, tasks, detached)
		}
		time.Sleep(time.Millisecond)
	}
}
