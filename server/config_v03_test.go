package server

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hi2shark/go-nowhere/diagnostic"
	"github.com/hi2shark/go-nowhere/wire"
)

func TestConfigRejectsUnknownAndDuplicateNetworks(t *testing.T) {
	for _, networks := range [][]Network{
		{"tpc"},
		{NetworkTCP, NetworkTCP},
	} {
		_, err := NewConfig(ConfigOptions{Password: "secret", Networks: networks})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("networks %v: got %v, want ErrInvalidConfig", networks, err)
		}
	}
}

func TestConfigDefaultsAndDefensiveNetworksCopy(t *testing.T) {
	config, err := NewConfig(ConfigOptions{Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if !config.TCPEnabled() || !config.UDPEnabled() {
		t.Fatalf("default networks: tcp=%v udp=%v", config.TCPEnabled(), config.UDPEnabled())
	}
	if config.Timeouts().Auth != DefaultAuthTimeout || config.Limits().PendingPairsGlobal != DefaultPendingPairsGlobal {
		t.Fatalf("defaults not normalized: %+v %+v", config.Timeouts(), config.Limits())
	}
	networks := config.Networks()
	networks[0] = "mutated"
	if config.Networks()[0] == "mutated" {
		t.Fatal("Networks exposed mutable backing storage")
	}
}

func TestLifecycleExactlyOnceAndRecoversCallbackPanic(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	var callbacks atomic.Int32
	var events atomic.Int32
	observer := diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
		if event.Code == "callback_panic" {
			events.Add(1)
		}
	})
	life := newLifecycle(context.Background(), left, func(error) {
		callbacks.Add(1)
		panic("host callback")
	}, observer)
	life.Close(errors.New("first"))
	life.Close(errors.New("second"))
	if callbacks.Load() != 1 || events.Load() != 1 {
		t.Fatalf("callbacks=%d panic_events=%d", callbacks.Load(), events.Load())
	}
}

func TestUpstreamHandoffPreservesCloseCause(t *testing.T) {
	config, err := NewConfig(ConfigOptions{Password: "secret", Networks: []Network{NetworkTCP}})
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("route failed")
	handler, err := NewHandler(HandlerOptions{
		Config: config,
		Upstream: upstreamFuncs{stream: func(context.Context, net.Conn, net.Addr, string) error {
			return wantErr
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	callback := make(chan error, 1)
	life := newLifecycle(context.Background(), left, func(err error) { callback <- err }, nil)
	owned := &ownedConn{Conn: left, life: life}
	if err := handler.routeStream(context.Background(), owned, nil, "example.com:443"); !errors.Is(err, wantErr) {
		t.Fatalf("routeStream=%v want %v", err, wantErr)
	}
	if err := <-callback; !errors.Is(err, wantErr) {
		t.Fatalf("callback=%v want %v", err, wantErr)
	}
}

func TestPairedCloseInvokesBothPhysicalCallbacksOnce(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	header := wire.FlowHeader{
		Role: wire.FlowRoleOpen, FlowID: 77, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	}
	first, firstPeer := net.Pipe()
	second, secondPeer := net.Pipe()
	defer firstPeer.Close()
	defer secondPeer.Close()
	var firstCalls, secondCalls atomic.Int32
	firstOwned := &ownedConn{Conn: first, life: newLifecycle(context.Background(), first, func(error) { firstCalls.Add(1) }, nil)}
	secondOwned := &ownedConn{Conn: second, life: newLifecycle(context.Background(), second, func(error) { secondCalls.Add(1) }, nil)}
	openHeader := header
	done := make(chan error, 1)
	go func() {
		_, err := manager.SubmitTCP(context.Background(), wire.SessionID{1}, openHeader, "example.com:443", firstOwned)
		done <- err
	}()
	time.Sleep(5 * time.Millisecond)
	header.Role = wire.FlowRoleAttach
	paired, err := manager.SubmitTCP(context.Background(), wire.SessionID{1}, header, "example.com:443", secondOwned)
	if err != nil {
		t.Fatal(err)
	}
	if err := paired.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = paired.Close()
	if firstCalls.Load() != 1 || secondCalls.Load() != 1 {
		t.Fatalf("callbacks first=%d second=%d", firstCalls.Load(), secondCalls.Load())
	}
}

func TestPairMetadataMismatchFailsOriginalHalf(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	first, firstPeer := net.Pipe()
	second, secondPeer := net.Pipe()
	defer firstPeer.Close()
	defer secondPeer.Close()
	header := wire.FlowHeader{
		Role: wire.FlowRoleOpen, FlowID: 42, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	}
	openHeader := header
	errCh := make(chan error, 1)
	go func() {
		_, err := manager.SubmitTCP(context.Background(), wire.SessionID{1}, openHeader, "a.example:443", first)
		errCh <- err
	}()
	time.Sleep(10 * time.Millisecond)
	header.Role = wire.FlowRoleAttach
	_, err := manager.SubmitTCP(context.Background(), wire.SessionID{1}, header, "b.example:443", second)
	if !errors.Is(err, ErrCarrierMismatch) {
		t.Fatalf("second half: %v, want ErrCarrierMismatch", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrCarrierMismatch) {
			t.Fatalf("first half: %v, want ErrCarrierMismatch", err)
		}
	case <-time.After(time.Second):
		t.Fatal("original half not released")
	}
}

func TestPairTimeoutPropagatesToPhysicalCallback(t *testing.T) {
	manager := newFlowPairManager(10 * time.Millisecond)
	defer manager.Close()
	left, right := net.Pipe()
	defer right.Close()
	callback := make(chan error, 1)
	life := newLifecycle(context.Background(), left, func(err error) { callback <- err }, nil)
	owned := &ownedConn{Conn: left, life: life}
	header := wire.FlowHeader{
		Role: wire.FlowRoleOpen, FlowID: 8, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	}
	_, err := manager.SubmitTCP(context.Background(), wire.SessionID{2}, header, "a.example:443", owned)
	if !errors.Is(err, ErrPairTimeout) {
		t.Fatalf("SubmitTCP: %v, want ErrPairTimeout", err)
	}
	select {
	case callbackErr := <-callback:
		if !errors.Is(callbackErr, ErrPairTimeout) {
			t.Fatalf("callback: %v, want ErrPairTimeout", callbackErr)
		}
	case <-time.After(time.Second):
		t.Fatal("callback not invoked")
	}
}

func TestAuthDeadlineJitterRangeAndFallback(t *testing.T) {
	config, err := NewConfig(ConfigOptions{Password: "secret", Networks: []Network{NetworkTCP}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(100, 0)
	handler.now = func() time.Time { return base }
	handler.randRead = func(buffer []byte) (int, error) {
		for i := range buffer {
			buffer[i] = 0xff
		}
		return len(buffer), nil
	}
	delay := handler.authDeadline().Sub(base)
	if delay < 4*time.Second || delay > 6*time.Second {
		t.Fatalf("jittered delay %v outside [4s,6s]", delay)
	}
	handler.randRead = func([]byte) (int, error) { return 0, errors.New("random unavailable") }
	if got := handler.authDeadline().Sub(base); got != DefaultAuthTimeout {
		t.Fatalf("fallback=%v want %v", got, DefaultAuthTimeout)
	}
}

func TestTCPAuthFailureWaitsForDeadlineAndClosesOnce(t *testing.T) {
	config, err := NewConfig(ConfigOptions{
		Password: "secret", Networks: []Network{NetworkTCP},
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
	serverConn, clientConn := net.Pipe()
	callback := make(chan error, 2)
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- handler.HandleConn(context.Background(), serverConn, &net.TCPAddr{IP: net.ParseIP("192.0.2.1")}, func(err error) {
			callback <- err
		})
	}()
	_, _ = clientConn.Write([]byte{0x00})
	_ = clientConn.Close()
	if err := <-done; err == nil {
		t.Fatal("invalid auth succeeded")
	}
	if elapsed := time.Since(start); elapsed < 10*time.Millisecond {
		t.Fatalf("auth failure returned before deadline: %v", elapsed)
	}
	if err := <-callback; err == nil {
		t.Fatal("callback lost auth failure")
	}
	select {
	case err := <-callback:
		t.Fatalf("callback invoked twice: %v", err)
	default:
	}
}

type noopUpstream struct{}

func (noopUpstream) HandleStream(context.Context, net.Conn, net.Addr, string) error { return nil }
func (noopUpstream) HandlePacket(context.Context, net.PacketConn, net.Addr, string) error {
	return nil
}

type upstreamFuncs struct {
	stream func(context.Context, net.Conn, net.Addr, string) error
	packet func(context.Context, net.PacketConn, net.Addr, string) error
}

func (u upstreamFuncs) HandleStream(ctx context.Context, conn net.Conn, source net.Addr, target string) error {
	return u.stream(ctx, conn, source, target)
}

func (u upstreamFuncs) HandlePacket(ctx context.Context, conn net.PacketConn, source net.Addr, target string) error {
	if u.packet == nil {
		return nil
	}
	return u.packet(ctx, conn, source, target)
}
