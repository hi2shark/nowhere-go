package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

func TestFlowPairManagerPairsTCP(t *testing.T) {
	m := newFlowPairManager(2 * time.Second)
	defer m.Close()

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

func TestParseTargetAddrInvalidPort(t *testing.T) {
	addr := parseTargetAddr("1.2.3.4:abc")
	if _, ok := addr.(*net.UDPAddr); ok {
		t.Fatalf("invalid port should not become UDPAddr: %#v", addr)
	}
	if addr.String() != "1.2.3.4:abc" {
		t.Fatalf("got %q", addr.String())
	}
}
