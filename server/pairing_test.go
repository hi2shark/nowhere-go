package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/diagnostic"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestFlowPairManagerPairsTCP(t *testing.T) {
	m := newFlowPairManager(2 * time.Second)
	defer m.Close()

	var (
		mu    sync.Mutex
		codes []string
		last  diagnostic.Event
	)
	m.setObserver(diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
		mu.Lock()
		codes = append(codes, event.Code)
		if event.Code == "pair_success" {
			last = event
		}
		mu.Unlock()
	}))

	c1, c2 := net.Pipe()
	c3, c4 := net.Pipe()
	defer c2.Close()
	defer c4.Close()

	session := wire.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	headerOpen := wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		Kind:     wire.FlowKindTCP,
		FlowID:   7,
		Uplink:   wire.CarrierTCP,
		Downlink: wire.CarrierUDP,
	}
	headerAttach := headerOpen
	headerAttach.Role = wire.FlowRoleAttach

	var wg sync.WaitGroup
	wg.Add(1)
	errCh := make(chan error, 1)
	go func() {
		defer wg.Done()
		paired, err := m.SubmitTCP(context.Background(), session, headerOpen, "1.2.3.4:80", c1)
		if err != nil {
			errCh <- err
			return
		}
		if paired != nil {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		errCh <- nil
	}()

	time.Sleep(20 * time.Millisecond)
	paired, err := m.SubmitTCP(context.Background(), session, headerAttach, "1.2.3.4:80", c3)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if paired == nil {
		t.Fatal("expected paired conn")
	}
	_ = paired.Close()

	if err := <-errCh; err != nil {
		t.Fatalf("open half: %v", err)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	foundSuccess := false
	for _, code := range codes {
		if code == "pair_success" {
			foundSuccess = true
		}
	}
	if !foundSuccess {
		t.Fatalf("codes=%v, want pair_success", codes)
	}
	if last.FlowID != 7 || last.SessionID != session || last.Target != "1.2.3.4:80" {
		t.Fatalf("pair_success fields = %+v", last)
	}
	if last.UplinkTransport != "tcp" || last.DownlinkTransport != "quic" {
		t.Fatalf("transports up=%s down=%s", last.UplinkTransport, last.DownlinkTransport)
	}
}

func TestFlowPairManagerTimeout(t *testing.T) {
	m := newFlowPairManager(50 * time.Millisecond)
	defer m.Close()

	c1, c2 := net.Pipe()
	defer c2.Close()

	session := wire.SessionID{}
	header := wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		Kind:     wire.FlowKindTCP,
		FlowID:   1,
		Uplink:   wire.CarrierTCP,
		Downlink: wire.CarrierUDP,
	}
	_, err := m.SubmitTCP(context.Background(), session, header, "1.2.3.4:80", c1)
	if err == nil {
		t.Fatal("expected timeout")
	}
}

func TestFlowPairManagerTCPCancelUnblocksPeer(t *testing.T) {
	m := newFlowPairManager(2 * time.Second)
	defer m.Close()

	c1, c2 := net.Pipe()
	defer c2.Close()

	session := wire.SessionID{9}
	header := wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		Kind:     wire.FlowKindTCP,
		FlowID:   3,
		Uplink:   wire.CarrierTCP,
		Downlink: wire.CarrierUDP,
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := m.SubmitTCP(ctx, session, header, "1.2.3.4:80", c1)
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SubmitTCP blocked after ctx cancel")
	}
}

func TestFlowPairManagerAttachFirstThenOpen(t *testing.T) {
	m := newFlowPairManager(2 * time.Second)
	defer m.Close()

	c1, c2 := net.Pipe()
	c3, c4 := net.Pipe()
	defer c2.Close()
	defer c4.Close()

	session := wire.SessionID{2}
	headerAttach := wire.FlowHeader{
		Role: wire.FlowRoleAttach, Kind: wire.FlowKindTCP, FlowID: 11,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	}
	headerOpen := headerAttach
	headerOpen.Role = wire.FlowRoleOpen

	errCh := make(chan error, 1)
	go func() {
		paired, err := m.SubmitTCP(context.Background(), session, headerAttach, "h:1", c1)
		if err != nil {
			errCh <- err
			return
		}
		if paired != nil {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		errCh <- nil
	}()
	time.Sleep(20 * time.Millisecond)
	paired, err := m.SubmitTCP(context.Background(), session, headerOpen, "h:1", c3)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if paired == nil {
		t.Fatal("expected paired conn")
	}
	_ = paired.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("attach half: %v", err)
	}
	m.mu.Lock()
	pending := len(m.pending)
	m.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending=%d, want 0", pending)
	}
}

func TestFlowPairManagerEmitsPairDiagnostics(t *testing.T) {
	m := newFlowPairManager(40 * time.Millisecond)
	defer m.Close()

	var mu sync.Mutex
	var codes []string
	m.setObserver(diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
		mu.Lock()
		codes = append(codes, event.Code)
		mu.Unlock()
		if event.Code == "pair_timeout" {
			if event.HalfRole != "open" || event.MissingHalf != "attach" || event.Transport != "tcp" {
				t.Errorf("pair_timeout fields role=%s missing=%s transport=%s", event.HalfRole, event.MissingHalf, event.Transport)
			}
			if event.ReceivedHalf != "open" || event.ExpectedTransport == "" {
				t.Errorf("pair_timeout received_half=%s expected_transport=%s", event.ReceivedHalf, event.ExpectedTransport)
			}
		}
	}))

	c1, c2 := net.Pipe()
	defer c2.Close()
	header := wire.FlowHeader{
		Role: wire.FlowRoleOpen, Kind: wire.FlowKindTCP, FlowID: 99,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	}
	_, err := m.SubmitTCPWithSource(context.Background(), wire.SessionID{1}, header, "h:1", c1, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	if err == nil {
		t.Fatal("expected timeout")
	}
	mu.Lock()
	defer mu.Unlock()
	foundWait, foundTimeout := false, false
	for _, code := range codes {
		if code == "pair_wait" {
			foundWait = true
		}
		if code == "pair_timeout" {
			foundTimeout = true
		}
	}
	if !foundWait || !foundTimeout {
		t.Fatalf("codes=%v, want pair_wait and pair_timeout", codes)
	}
	m.mu.Lock()
	pending := len(m.pending)
	m.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending=%d after timeout, want 0", pending)
	}
}

func TestParseTargetAddrInvalidPort(t *testing.T) {
	addr := parseTargetAddr("1.2.3.4:abc")
	if _, ok := addr.(*net.UDPAddr); ok {
		t.Fatalf("invalid port should not become UDPAddr: %#v", addr)
	}
	if addr.String() != "1.2.3.4:abc" {
		t.Fatalf("got %q", addr.String())
	}
}
