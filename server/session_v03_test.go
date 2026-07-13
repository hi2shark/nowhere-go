package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

func TestSessionManagerLimitAndReplacement(t *testing.T) {
	manager := newSessionManager()
	manager.configureLimit(1)
	firstConn := &fakeQuicConn{}
	first := newPortalSession(wire.SessionID{1}, firstConn, nil, nil)
	if err := manager.Register(first); err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(newPortalSession(wire.SessionID{2}, &fakeQuicConn{}, nil, nil)); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("Register second session = %v, want ErrSessionLimit", err)
	}
	replacement := newPortalSession(wire.SessionID{1}, &fakeQuicConn{}, nil, nil)
	if err := manager.Register(replacement); err != nil {
		t.Fatalf("replacement: %v", err)
	}
	if firstConn.closed.Load() != 1 {
		t.Fatalf("replaced session close count=%d want 1", firstConn.closed.Load())
	}
	manager.Close()
}

func TestCompactQueueDropsNewAndReleasesBudget(t *testing.T) {
	config, err := NewConfig(ConfigOptions{
		Password: "secret",
		Limits:   Limits{QUICQueuePackets: 1, QUICQueueBytes: 64, QUICFlowsPerSession: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}})
	if err != nil {
		t.Fatal(err)
	}
	session := newPortalSession(wire.SessionID{1}, &fakeQuicConn{}, handler, nil)
	flow := newCompactUDPFlow(session, 1, "example.com:53", wire.CarrierUDP)
	if !session.putFlow(1, flow) {
		t.Fatal("putFlow failed")
	}
	flow.deliver([]byte("first"))
	flow.deliver([]byte("second"))
	buffer := make([]byte, 16)
	n, _, err := flow.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "first" {
		t.Fatalf("queue reordered/dropped old packet: %q", got)
	}
	session.mu.Lock()
	queued := session.queuedBytes
	session.mu.Unlock()
	if queued != 0 {
		t.Fatalf("queued bytes=%d want 0", queued)
	}
	_ = flow.Close()
}

func TestCompactPacketDeadline(t *testing.T) {
	config, _ := NewConfig(ConfigOptions{Password: "secret"})
	handler, _ := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}})
	session := newPortalSession(wire.SessionID{1}, &fakeQuicConn{}, handler, nil)
	flow := newCompactUDPFlow(session, 1, "example.com:53", wire.CarrierUDP)
	_ = flow.SetReadDeadline(time.Now().Add(-time.Millisecond))
	if _, _, err := flow.ReadFrom(make([]byte, 1)); !errors.Is(err, deadlineError()) {
		t.Fatalf("ReadFrom deadline = %v", err)
	}
	_ = flow.Close()
}

func TestQUICAuthRejectsTrailingByteAtDeadline(t *testing.T) {
	config, err := NewConfig(ConfigOptions{
		Password: "secret",
		Timeouts: Timeouts{Auth: 15 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}})
	if err != nil {
		t.Fatal(err)
	}
	handler.randRead = func([]byte) (int, error) { return 0, errors.New("fallback") }
	frame, err := wire.MakeAuthFrameWithSession("secret", config.EffectiveSpec(), wire.SessionID{1})
	if err != nil {
		t.Fatal(err)
	}
	stream := &fakeQuicStream{reader: bytes.NewReader(append(frame, 0xff))}
	conn := &fakeQuicConn{stream: stream}
	start := time.Now()
	_, _, err = handler.authenticateQuic(context.Background(), conn)
	if !errors.Is(err, wire.ErrInvalidFrame) {
		t.Fatalf("authenticateQuic = %v, want ErrInvalidFrame", err)
	}
	if elapsed := time.Since(start); elapsed < 10*time.Millisecond {
		t.Fatalf("invalid auth returned before deadline: %v", elapsed)
	}
}

func TestQUICAuthRejectsMissingFIN(t *testing.T) {
	config, err := NewConfig(ConfigOptions{
		Password: "secret",
		Timeouts: Timeouts{Auth: 10 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}})
	if err != nil {
		t.Fatal(err)
	}
	handler.randRead = func([]byte) (int, error) { return 0, errors.New("fallback") }
	frame, err := wire.MakeAuthFrameWithSession("secret", config.EffectiveSpec(), wire.SessionID{1})
	if err != nil {
		t.Fatal(err)
	}
	stream := &fakeQuicStream{reader: bytes.NewReader(frame), missingFIN: true}
	_, _, err = handler.authenticateQuic(context.Background(), &fakeQuicConn{stream: stream})
	if !errors.Is(err, wire.ErrInvalidFrame) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("authenticateQuic = %v, want invalid frame/deadline", err)
	}
}

func TestPairGlobalLimit(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	manager.configureLimits(Limits{PendingPairsPerSession: 1, PendingPairsGlobal: 1})
	header := wire.FlowHeader{
		Role: wire.FlowRoleOpen, FlowID: 1, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	}
	first, firstPeer := net.Pipe()
	defer firstPeer.Close()
	done := make(chan error, 1)
	go func() {
		_, err := manager.SubmitTCP(context.Background(), wire.SessionID{1}, header, "example.com:443", first)
		done <- err
	}()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		manager.mu.Lock()
		count := len(manager.pending)
		manager.mu.Unlock()
		if count == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	second, secondPeer := net.Pipe()
	defer secondPeer.Close()
	header.FlowID = 2
	if _, err := manager.SubmitTCP(context.Background(), wire.SessionID{2}, header, "example.com:443", second); !errors.Is(err, ErrPairLimit) {
		t.Fatalf("second pair = %v, want ErrPairLimit", err)
	}
	_ = second.Close()
	manager.Close()
	if err := <-done; !errors.Is(err, ErrClosed) {
		t.Fatalf("first pair close = %v, want ErrClosed", err)
	}
}
