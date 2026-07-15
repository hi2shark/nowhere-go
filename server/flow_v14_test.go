package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

func TestTCPDuplexWritesReadyAfterTargetDial(t *testing.T) {
	handler, config := newFlowTestHandler(t, upstreamFuncs{
		stream: func(_ context.Context, _ net.Conn, _ net.Addr, target string, readiness FlowReadiness) error {
			if target != "example.com:443" {
				t.Fatalf("target = %q", target)
			}
			return readiness.Ready()
		},
	}, Timeouts{})

	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 1, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	}
	client, done := startTCPFlow(t, handler, config, wire.SessionID{1}, header, "example.com:443")
	defer client.Close()

	assertFlowResult(t, client, wire.FlowResult{Status: wire.FlowStatusReady})
	if err := <-done; err != nil {
		t.Fatalf("HandleConn = %v", err)
	}
}

func TestTCPDuplexDialFailureWritesReject(t *testing.T) {
	handler, config := newFlowTestHandler(t, upstreamFuncs{
		stream: func(context.Context, net.Conn, net.Addr, string, FlowReadiness) error {
			return errors.New("dial failed")
		},
	}, Timeouts{})

	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 2, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	}
	client, done := startTCPFlow(t, handler, config, wire.SessionID{2}, header, "example.com:443")
	defer client.Close()

	assertFlowResult(t, client, wire.FlowResult{
		Status: wire.FlowStatusReject,
		Code:   wire.FlowErrorCodeDialFailed,
	})
	if err := <-done; err == nil {
		t.Fatal("HandleConn unexpectedly succeeded")
	}
}

func TestSplitTCPAttachIsHeaderOnlyAndInheritsOpenTarget(t *testing.T) {
	handler, config := newFlowTestHandler(t, upstreamFuncs{
		stream: func(_ context.Context, _ net.Conn, _ net.Addr, target string, readiness FlowReadiness) error {
			if target != "example.com:443" {
				t.Fatalf("target = %q", target)
			}
			return readiness.Ready()
		},
	}, Timeouts{RequestIdle: 100 * time.Millisecond})

	sessionID := wire.SessionID{3}
	session := newPortalSession(sessionID, &fakeQuicConn{}, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	openHeader := wire.FlowHeader{
		Role: wire.FlowRoleOpen, FlowID: 7, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	}
	attachHeader := openHeader
	attachHeader.Role = wire.FlowRoleAttach

	openClient, openDone := startTCPFlow(t, handler, config, sessionID, openHeader, "example.com:443")
	defer openClient.Close()
	attachSetup, err := wire.EncodeFlowSetup(attachHeader, "", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	attachStream := newRecordingQuicStream(attachSetup)
	session.handleStream(context.Background(), attachStream)
	for deadline := time.Now().Add(time.Second); len(attachStream.writtenBytes()) < wire.FlowResultLen && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}

	assertFlowResult(t, bytes.NewReader(attachStream.writtenBytes()), wire.FlowResult{Status: wire.FlowStatusReady})
	_ = openClient.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	var one [1]byte
	if _, err := openClient.Read(one[:]); err == nil {
		t.Fatal("uplink unexpectedly received FLOW_RESULT")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("uplink read = %v, want timeout", err)
	}

	if err := <-openDone; err != nil {
		t.Fatalf("open HandleConn = %v", err)
	}
}

func TestAttachPairTimeoutWritesRejectOnSelectedDownlink(t *testing.T) {
	handler, config := newFlowTestHandler(t, noopUpstream{}, Timeouts{
		FlowPair:    20 * time.Millisecond,
		RequestIdle: 200 * time.Millisecond,
	})
	header := wire.FlowHeader{
		Role: wire.FlowRoleAttach, FlowID: 8, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierTCP,
	}
	client, done := startTCPFlow(t, handler, config, wire.SessionID{4}, header, "")
	defer client.Close()

	assertFlowResult(t, client, wire.FlowResult{
		Status: wire.FlowStatusReject,
		Code:   wire.FlowErrorCodePairTimeout,
	})
	if err := <-done; !errors.Is(err, ErrPairTimeout) {
		t.Fatalf("HandleConn = %v, want ErrPairTimeout", err)
	}
}

func TestTCPUDPDuplexUsesTypedUOTReady(t *testing.T) {
	handler, config := newFlowTestHandler(t, upstreamFuncs{
		packet: func(_ context.Context, _ net.PacketConn, _ net.Addr, target string, readiness FlowReadiness) error {
			if target != "example.com:53" {
				t.Fatalf("target = %q", target)
			}
			return readiness.Ready()
		},
	}, Timeouts{})

	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 9, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	}
	client, done := startTCPFlow(t, handler, config, wire.SessionID{5}, header, "example.com:53")
	defer client.Close()

	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := wire.ReadUOTFrame(client)
	if err != nil {
		t.Fatalf("ReadUOTFrame = %v", err)
	}
	if frame.Kind != wire.UOTFrameReady {
		t.Fatalf("frame = %+v, want READY", frame)
	}
	if err := <-done; err != nil {
		t.Fatalf("HandleConn = %v", err)
	}
}

func TestTCPUDPDuplexDialFailureUsesTypedUOTReject(t *testing.T) {
	handler, config := newFlowTestHandler(t, upstreamFuncs{
		packet: func(context.Context, net.PacketConn, net.Addr, string, FlowReadiness) error {
			return errors.New("UDP dial failed")
		},
	}, Timeouts{})

	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 10, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	}
	client, done := startTCPFlow(t, handler, config, wire.SessionID{6}, header, "example.com:53")
	defer client.Close()

	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := wire.ReadUOTFrame(client)
	if err != nil {
		t.Fatalf("ReadUOTFrame = %v", err)
	}
	if frame.Kind != wire.UOTFrameReject || frame.Code != wire.FlowErrorCodeDialFailed {
		t.Fatalf("frame = %+v, want DIAL_FAILED REJECT", frame)
	}
	if err := <-done; err == nil {
		t.Fatal("HandleConn unexpectedly succeeded")
	}
}

func TestQUICUDPDuplexUsesF2ControlResult(t *testing.T) {
	handler, _ := newFlowTestHandler(t, upstreamFuncs{
		packet: func(_ context.Context, _ net.PacketConn, _ net.Addr, target string, readiness FlowReadiness) error {
			if target != "example.com:53" {
				t.Fatalf("target = %q", target)
			}
			return readiness.Ready()
		},
	}, Timeouts{})

	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 10, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}
	setup, err := wire.EncodeFlowSetup(header, "example.com:53", handler.config.spec)
	if err != nil {
		t.Fatal(err)
	}
	stream := newRecordingQuicStream(setup)
	session := newPortalSession(wire.SessionID{6}, &fakeQuicConn{}, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	session.handleStream(context.Background(), stream)

	assertFlowResult(t, bytes.NewReader(stream.writtenBytes()), wire.FlowResult{Status: wire.FlowStatusReady})
}

func TestQUICUDPDuplexDialFailureUsesF2Reject(t *testing.T) {
	handler, _ := newFlowTestHandler(t, upstreamFuncs{
		packet: func(context.Context, net.PacketConn, net.Addr, string, FlowReadiness) error {
			return errors.New("UDP dial failed")
		},
	}, Timeouts{})

	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 11, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}
	setup, err := wire.EncodeFlowSetup(header, "example.com:53", handler.config.spec)
	if err != nil {
		t.Fatal(err)
	}
	stream := newRecordingQuicStream(setup)
	session := newPortalSession(wire.SessionID{7}, &fakeQuicConn{}, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	session.handleStream(context.Background(), stream)

	assertFlowResult(t, bytes.NewReader(stream.writtenBytes()), wire.FlowResult{
		Status: wire.FlowStatusReject,
		Code:   wire.FlowErrorCodeDialFailed,
	})
}

func TestNOWUFragmentsAreReassembledBeforeDelivery(t *testing.T) {
	handler, _ := newFlowTestHandler(t, noopUpstream{}, Timeouts{})
	session := newPortalSession(wire.SessionID{7}, &fakeQuicConn{}, handler, nil)
	flow := newNowuFlow(session, 11, "example.com:53")
	if !session.putFlow(11, flow) {
		t.Fatal("putFlow failed")
	}
	frames, err := wire.EncodeUDPDataFragments(11, 1, []byte("fragmented"), nowuDataHeaderLen+4)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 2 {
		t.Fatalf("fragment count = %d", len(frames))
	}

	type readResult struct {
		n   int
		err error
		buf [32]byte
	}
	readDone := make(chan readResult, 1)
	go func() {
		var result readResult
		result.n, _, result.err = flow.ReadFrom(result.buf[:])
		readDone <- result
	}()

	session.handleNowu(context.Background(), frames[0])
	select {
	case result := <-readDone:
		t.Fatalf("partial fragment delivered: n=%d err=%v payload=%q", result.n, result.err, result.buf[:result.n])
	case <-time.After(20 * time.Millisecond):
	}
	for _, frame := range frames[1:] {
		session.handleNowu(context.Background(), frame)
	}
	select {
	case result := <-readDone:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if got := string(result.buf[:result.n]); got != "fragmented" {
			t.Fatalf("payload = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("reassembled packet not delivered")
	}
	_ = flow.Close()
}

func TestQUICTCPDuplexRoutesPayloadWithoutSetupFIN(t *testing.T) {
	payload := []byte("payload-after-flow-setup")
	handler, _ := newFlowTestHandler(t, upstreamFuncs{
		stream: func(_ context.Context, conn net.Conn, _ net.Addr, target string, readiness FlowReadiness) error {
			if target != "example.com:443" {
				t.Fatalf("target = %q", target)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				return err
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload = %q, want %q", got, payload)
			}
			if err := readiness.Ready(); err != nil {
				return err
			}
			return conn.Close()
		},
	}, Timeouts{})
	header := wire.FlowHeader{
		Role: wire.FlowRoleDuplex, FlowID: 12, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierUDP, Downlink: wire.CarrierUDP,
	}
	setup, err := wire.EncodeFlowSetup(header, "example.com:443", handler.config.spec)
	if err != nil {
		t.Fatal(err)
	}
	stream := newRecordingQuicStream(append(setup, payload...))
	session := newPortalSession(wire.SessionID{8}, &fakeQuicConn{}, handler, &net.UDPAddr{})
	if err := handler.sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	session.handleStream(context.Background(), stream)
	assertFlowResult(t, bytes.NewReader(stream.writtenBytes()), wire.FlowResult{Status: wire.FlowStatusReady})
}

func newFlowTestHandler(t *testing.T, upstream Upstream, timeouts Timeouts) (*Handler, *Config) {
	t.Helper()
	config, err := NewConfig(ConfigOptions{Password: "secret", Timeouts: timeouts})
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

func startTCPFlow(t *testing.T, handler *Handler, config *Config, sessionID wire.SessionID, header wire.FlowHeader, target string) (net.Conn, <-chan error) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- handler.HandleConn(context.Background(), serverConn, &net.TCPAddr{}, nil)
	}()
	auth, err := wire.MakeAuthFrameWithSession("secret", config.EffectiveSpec(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := wire.EncodeFlowSetup(header, target, config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = clientConn.Write(append(auth, setup...))
	}()
	return clientConn, done
}

func assertFlowResult(t *testing.T, reader io.Reader, want wire.FlowResult) {
	t.Helper()
	if conn, ok := reader.(net.Conn); ok {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	}
	got, err := wire.ReadFlowResult(reader)
	if err != nil {
		t.Fatalf("ReadFlowResult = %v", err)
	}
	if got != want {
		t.Fatalf("FlowResult = %+v, want %+v", got, want)
	}
}

type recordingQuicStream struct {
	reader *bytes.Reader
	mu     sync.Mutex
	writer bytes.Buffer
}

func newRecordingQuicStream(input []byte) *recordingQuicStream {
	return &recordingQuicStream{reader: bytes.NewReader(input)}
}

func (s *recordingQuicStream) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s *recordingQuicStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writer.Write(p)
}
func (s *recordingQuicStream) writtenBytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.writer.Bytes()...)
}
func (s *recordingQuicStream) Close() error                     { return nil }
func (s *recordingQuicStream) SetDeadline(time.Time) error      { return nil }
func (s *recordingQuicStream) SetReadDeadline(time.Time) error  { return nil }
func (s *recordingQuicStream) SetWriteDeadline(time.Time) error { return nil }
func (s *recordingQuicStream) CancelRead(uint64)                {}
func (s *recordingQuicStream) CancelWrite(uint64)               {}

var _ QuicStream = (*recordingQuicStream)(nil)
