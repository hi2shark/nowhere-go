package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

func TestTask6RealUDPPermitSharedAndReleasedOnRouteClose(t *testing.T) {
	packets := make(chan net.PacketConn, 2)
	handler, config := newTask6IntegrationHandler(t, upstreamFuncs{
		packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
			if err := readiness.Ready(); err != nil {
				return err
			}
			packets <- pc
			return nil
		},
	}, Timeouts{})
	sessionID := wire.SessionID{0x71}
	session := registerTask6Session(t, handler, sessionID)

	tcpHeader := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	}
	tcpClient, tcpDone := startTCPFlow(t, handler, config, sessionID, tcpHeader, "example.com:53")
	defer tcpClient.Close()
	assertTask6UOTFrame(t, tcpClient, wire.UOTFrame{Kind: wire.UOTFrameReady})
	firstPacket := receiveTask6Packet(t, packets)
	select {
	case err := <-tcpDone:
		if err != nil {
			t.Fatalf("TCP/UoT HandleConn = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP/UoT HandleConn did not return")
	}

	limited := runTask6QUICUDPFlow(t, session, wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 2, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}, "example.com:53")
	assertFlowResult(t, bytes.NewReader(limited.writtenBytes()), wire.FlowResult{
		Status: wire.FlowStatusReject,
		Code:   wire.FlowErrorCodeFlowLimit,
	})
	select {
	case pc := <-packets:
		_ = pc.Close()
		t.Fatal("flow-limited QUIC request reached upstream")
	default:
	}

	if err := firstPacket.Close(); err != nil {
		t.Fatal(err)
	}
	waitTask6UDPPermitCount(t, handler.claims, sessionID, session.Generation, 0)

	retry := runTask6QUICUDPFlow(t, session, wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 3, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}, "example.com:53")
	assertFlowResult(t, bytes.NewReader(retry.writtenBytes()), wire.FlowResult{Status: wire.FlowStatusReady})
	if err := receiveTask6Packet(t, packets).Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTask6RealUDPPermitReleasedOnDialFailure(t *testing.T) {
	var dials atomic.Int32
	dialErr := errors.New("UDP dial failed")
	handler, config := newTask6IntegrationHandler(t, NewDialUpstream(&task6Dialer{
		dial: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, dialErr
		},
	}), Timeouts{})
	sessionID := wire.SessionID{0x72}
	session := registerTask6Session(t, handler, sessionID)

	tcpHeader := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	}
	tcpClient, tcpDone := startTCPFlow(t, handler, config, sessionID, tcpHeader, "example.com:53")
	defer tcpClient.Close()
	assertTask6UOTFrame(t, tcpClient, wire.UOTFrame{
		Kind: wire.UOTFrameReject,
		Code: wire.FlowErrorCodeDialFailed,
	})
	select {
	case err := <-tcpDone:
		if !errors.Is(err, dialErr) {
			t.Fatalf("TCP/UoT HandleConn = %v, want dial error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP/UoT dial failure did not return")
	}
	waitTask6UDPPermitCount(t, handler.claims, sessionID, session.Generation, 0)

	quic := runTask6QUICUDPFlow(t, session, wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 2, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}, "example.com:53")
	assertFlowResult(t, bytes.NewReader(quic.writtenBytes()), wire.FlowResult{
		Status: wire.FlowStatusReject,
		Code:   wire.FlowErrorCodeDialFailed,
	})
	if got := dials.Load(); got != 2 {
		t.Fatalf("UDP dial calls = %d, want 2", got)
	}
}

func TestTask6RealUDPPermitReleasedOnPairTimeout(t *testing.T) {
	var upstreamCalls atomic.Int32
	handler, config := newTask6IntegrationHandler(t, upstreamFuncs{
		packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
			upstreamCalls.Add(1)
			if err := readiness.Ready(); err != nil {
				return err
			}
			return pc.Close()
		},
	}, Timeouts{FlowPair: 20 * time.Millisecond, RequestIdle: time.Second})
	sessionID := wire.SessionID{0x73}
	session := registerTask6Session(t, handler, sessionID)

	openHeader := wire.FlowHeader{
		Role: wire.FlowRoleOpen, FlowID: 1, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	}
	openClient, openDone := startTCPFlow(t, handler, config, sessionID, openHeader, "example.com:53")
	defer openClient.Close()
	select {
	case err := <-openDone:
		if !errors.Is(err, ErrPairTimeout) {
			t.Fatalf("TCP/UoT pair timeout = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP/UoT pair timeout did not fire")
	}
	waitTask6UDPPermitCount(t, handler.claims, sessionID, session.Generation, 0)

	quic := runTask6QUICUDPFlow(t, session, wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 2, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}, "example.com:53")
	assertFlowResult(t, bytes.NewReader(quic.writtenBytes()), wire.FlowResult{Status: wire.FlowStatusReady})
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
}

func TestTask6RealUDPPermitReleasedOnSessionReplacement(t *testing.T) {
	packets := make(chan net.PacketConn, 2)
	handler, config := newTask6IntegrationHandler(t, upstreamFuncs{
		packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
			if err := readiness.Ready(); err != nil {
				return err
			}
			packets <- pc
			return nil
		},
	}, Timeouts{})
	sessionID := wire.SessionID{0x74}
	oldSession := registerTask6Session(t, handler, sessionID)

	tcpHeader := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	}
	tcpClient, tcpDone := startTCPFlow(t, handler, config, sessionID, tcpHeader, "example.com:53")
	defer tcpClient.Close()
	assertTask6UOTFrame(t, tcpClient, wire.UOTFrame{Kind: wire.UOTFrameReady})
	oldPacket := receiveTask6Packet(t, packets)
	select {
	case err := <-tcpDone:
		if err != nil {
			t.Fatalf("TCP/UoT HandleConn = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP/UoT HandleConn did not return")
	}

	newSession := registerTask6Session(t, handler, sessionID)
	if newSession.Generation != oldSession.Generation+1 {
		t.Fatalf("replacement generation = %d, want %d", newSession.Generation, oldSession.Generation+1)
	}
	waitTask6UDPPermitCount(t, handler.claims, sessionID, oldSession.Generation, 0)
	_ = oldPacket.Close()

	quic := runTask6QUICUDPFlow(t, newSession, wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 2, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}, "example.com:53")
	assertFlowResult(t, bytes.NewReader(quic.writtenBytes()), wire.FlowResult{Status: wire.FlowStatusReady})
	if err := receiveTask6Packet(t, packets).Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTask6RealCrossCarrierResultSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want wire.UOTFrame
	}{
		{name: "ready", want: wire.UOTFrame{Kind: wire.UOTFrameReady}},
		{name: "reject", err: errors.New("dial failed"), want: wire.UOTFrame{Kind: wire.UOTFrameReject, Code: wire.FlowErrorCodeDialFailed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, config := newTask6IntegrationHandler(t, upstreamFuncs{
				packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, _ string, readiness FlowReadiness) error {
					if tc.err != nil {
						return tc.err
					}
					if err := readiness.Ready(); err != nil {
						return err
					}
					return pc.Close()
				},
			}, Timeouts{FlowPair: time.Second})
			sessionID := wire.SessionID{0x75, byte(len(tc.name))}
			session := registerTask6Session(t, handler, sessionID)

			header := wire.FlowHeader{
				Role: wire.FlowRoleOpen, FlowID: 1, Kind: wire.FlowKindUDP,
				Uplink: wire.CarrierUDP, Downlink: wire.CarrierTCP,
			}
			setup, err := wire.EncodeFlowSetup(header, "example.com:53", config.EffectiveSpec())
			if err != nil {
				t.Fatal(err)
			}
			control := newRecordingQuicStream(setup)
			quicDone := make(chan struct{})
			go func() {
				session.handleStream(context.Background(), control)
				close(quicDone)
			}()
			waitTask6Entries(t, handler.claims, 1)

			header.Role = wire.FlowRoleAttach
			tcpClient, tcpDone := startTCPFlow(t, handler, config, sessionID, header, "")
			defer tcpClient.Close()
			assertTask6UOTFrame(t, tcpClient, tc.want)
			select {
			case err := <-tcpDone:
				if tc.err == nil && err != nil {
					t.Fatalf("TCP attach = %v", err)
				}
				if tc.err != nil && !errors.Is(err, tc.err) {
					t.Fatalf("TCP attach = %v, want %v", err, tc.err)
				}
			case <-time.After(time.Second):
				t.Fatal("TCP attach did not return")
			}
			select {
			case <-quicDone:
			case <-time.After(time.Second):
				t.Fatal("QUIC open did not finish pairing")
			}
			if payload := control.writtenBytes(); len(payload) != 0 {
				t.Fatalf("QUIC uplink control received downlink result: %x", payload)
			}
		})
	}
}

func TestTask6RealQUICCarrierConflictUsesMetadataConflict(t *testing.T) {
	var upstreamCalls atomic.Int32
	handler, config := newTask6IntegrationHandler(t, upstreamFuncs{
		stream: func(context.Context, net.Conn, net.Addr, string, FlowReadiness) error {
			upstreamCalls.Add(1)
			return nil
		},
	}, Timeouts{})
	session := registerTask6Session(t, handler, wire.SessionID{0x76})
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	}
	setup, err := wire.EncodeFlowSetup(header, "example.com:443", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	control := newRecordingQuicStream(setup)
	session.handleStream(context.Background(), control)
	assertFlowResult(t, bytes.NewReader(control.writtenBytes()), wire.FlowResult{
		Status: wire.FlowStatusReject,
		Code:   wire.FlowErrorCodeMetadataConflict,
	})
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("carrier-conflicting request reached upstream %d times", got)
	}
}

func newTask6IntegrationHandler(t *testing.T, upstream Upstream, timeouts Timeouts) (*Handler, *Config) {
	t.Helper()
	config, err := NewConfig(ConfigOptions{
		Password: "secret",
		Timeouts: timeouts,
		Limits:   task6Limits(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: upstream})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	return handler, config
}

func registerTask6Session(t *testing.T, handler *Handler, sessionID wire.SessionID) *portalSession {
	t.Helper()
	session := newPortalSession(sessionID, &fakeQuicConn{}, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	return session
}

func runTask6QUICUDPFlow(t *testing.T, session *portalSession, header wire.FlowHeader, target string) *recordingQuicStream {
	t.Helper()
	setup, err := wire.EncodeFlowSetup(header, target, session.Handler.config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	stream := newRecordingQuicStream(setup)
	session.handleStream(context.Background(), stream)
	return stream
}

func assertTask6UOTFrame(t *testing.T, conn net.Conn, want wire.UOTFrame) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := wire.ReadUOTFrame(conn)
	if err != nil {
		t.Fatalf("ReadUOTFrame = %v", err)
	}
	if got.Kind != want.Kind || got.Code != want.Code {
		t.Fatalf("UOT frame = %+v, want %+v", got, want)
	}
}

func receiveTask6Packet(t *testing.T, packets <-chan net.PacketConn) net.PacketConn {
	t.Helper()
	select {
	case packet := <-packets:
		return packet
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive packet flow")
		return nil
	}
}

func waitTask6UDPPermitCount(t *testing.T, registry *claimRegistry, sessionID wire.SessionID, generation uint64, want int) {
	t.Helper()
	key := sessionGeneration{sessionID: sessionID, generation: generation}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		registry.mu.Lock()
		got := registry.udpInUse[key]
		registry.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	registry.mu.Lock()
	got := registry.udpInUse[key]
	registry.mu.Unlock()
	t.Fatalf("UDP permits for generation %d = %d, want %d", generation, got, want)
}
