package bundle

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestQUICDatagramMuxConcurrentFlowsDoNotStealFrames(t *testing.T) {
	raw := newMuxTestSession()
	backend := &muxTestBackend{session: raw}
	managed := newQUICMuxBackend(backend)

	first, err := managed.AcquireSession(context.Background())
	if err != nil {
		t.Fatalf("AcquireSession first: %v", err)
	}
	second, err := managed.AcquireSession(context.Background())
	if err != nil {
		t.Fatalf("AcquireSession second: %v", err)
	}
	if first != second {
		t.Fatal("same physical session produced different mux states")
	}
	session := first.(*quicSessionMux)
	flow1, err := session.register(1)
	if err != nil {
		t.Fatalf("register flow 1: %v", err)
	}
	flow2, err := session.register(2)
	if err != nil {
		t.Fatalf("register flow 2: %v", err)
	}

	flow1Frames := mustMuxFrames(t, 1, 11, []byte("flow-one-payload"), nowuDataHeaderLen+4)
	flow2Frames := mustMuxFrames(t, 2, 22, []byte("flow-two"), nowuDataHeaderLen+64)
	unknownFrames := mustMuxFrames(t, 99, 33, []byte("ignored"), nowuDataHeaderLen+64)

	flow1Result := make(chan muxReadResult, 1)
	flow2Result := make(chan muxReadResult, 1)
	go readMuxPacket(flow1, flow1Result)
	go readMuxPacket(flow2, flow2Result)

	raw.push(unknownFrames[0], nil)
	raw.push(flow1Frames[1], nil)
	raw.push(flow2Frames[0], nil)
	for _, frame := range flow1Frames[2:] {
		raw.push(frame, nil)
	}
	raw.push(flow1Frames[0], nil)

	assertMuxPayload(t, flow1Result, "flow-one-payload")
	assertMuxPayload(t, flow2Result, "flow-two")
	if got := raw.maxConcurrent.Load(); got != 1 {
		t.Fatalf("concurrent ReceiveDatagram calls = %d, want 1", got)
	}

	closeFrame, err := wire.EncodeUDPClose(1)
	if err != nil {
		t.Fatalf("EncodeUDPClose: %v", err)
	}
	raw.push(closeFrame, nil)
	if _, err := flow1.readPacket(context.Background(), nil); !errors.Is(err, io.EOF) {
		t.Fatalf("flow 1 close error = %v, want EOF", err)
	}
	session.mu.Lock()
	_, flow1Registered := session.flows[1]
	_, flow2Registered := session.flows[2]
	session.mu.Unlock()
	if flow1Registered || !flow2Registered {
		t.Fatalf("registrations after CLOSE: flow1=%v flow2=%v", flow1Registered, flow2Registered)
	}

	flow2Again := make(chan muxReadResult, 1)
	go readMuxPacket(flow2, flow2Again)
	for _, frame := range mustMuxFrames(t, 2, 23, []byte("still-open"), nowuDataHeaderLen+64) {
		raw.push(frame, nil)
	}
	assertMuxPayload(t, flow2Again, "still-open")

	wantErr := errors.New("test: physical session failed")
	raw.push(nil, wantErr)
	if _, err := flow2.readPacket(context.Background(), nil); !errors.Is(err, wantErr) {
		t.Fatalf("flow 2 session error = %v, want %v", err, wantErr)
	}
	select {
	case <-session.loopDone:
	case <-time.After(time.Second):
		t.Fatal("mux receive loop did not stop after session failure")
	}
}

func TestQUICUDPIdenticalDuplicateBeforeLengthCheckIsIgnored(t *testing.T) {
	raw := newMuxTestSession()
	managed := newQUICMuxBackend(&muxTestBackend{session: raw})
	t.Cleanup(func() { _ = managed.Close() })
	sessionValue, err := managed.AcquireSession(context.Background())
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	flow, err := sessionValue.(*quicSessionMux).register(1)
	if err != nil {
		t.Fatalf("register flow: %v", err)
	}

	frames := mustMuxFrames(t, 1, 11, []byte("abc"), nowuDataHeaderLen+2)
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want 2", len(frames))
	}
	result := make(chan muxReadResult, 1)
	go readMuxPacket(flow, result)
	raw.push(frames[0], nil)
	raw.push(append([]byte(nil), frames[0]...), nil)
	raw.push(frames[1], nil)
	assertMuxPayload(t, result, "abc")
}

func TestQUICUDPConflictingDuplicateDropsOnlyCurrentPacket(t *testing.T) {
	raw := newMuxTestSession()
	managed := newQUICMuxBackend(&muxTestBackend{session: raw})
	t.Cleanup(func() { _ = managed.Close() })
	sessionValue, err := managed.AcquireSession(context.Background())
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	flow, err := sessionValue.(*quicSessionMux).register(1)
	if err != nil {
		t.Fatalf("register flow: %v", err)
	}

	conflicted := mustMuxFrames(t, 1, 11, []byte("abc"), nowuDataHeaderLen+2)
	changed := append([]byte(nil), conflicted[0]...)
	changed[len(changed)-1] ^= 0xff
	raw.push(conflicted[0], nil)
	raw.push(changed, nil)
	raw.push(conflicted[1], nil)

	result := make(chan muxReadResult, 1)
	go readMuxPacket(flow, result)
	for _, frame := range mustMuxFrames(t, 1, 12, []byte("next"), nowuDataHeaderLen+64) {
		raw.push(frame, nil)
	}
	assertMuxPayload(t, result, "next")
}

func TestCarrierBundleCloseStopsQUICReceiveLoop(t *testing.T) {
	raw := newMuxTestSession()
	managed := newQUICMuxBackend(&muxTestBackend{session: raw})
	sessionValue, err := managed.AcquireSession(context.Background())
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	session := sessionValue.(*quicSessionMux)
	flow, err := session.register(7)
	if err != nil {
		t.Fatalf("register flow: %v", err)
	}

	select {
	case <-raw.receiveStarted:
	case <-time.After(time.Second):
		t.Fatal("receive loop did not start")
	}

	bundle := &CarrierBundle{cfg: bundleConfig{up: wire.CarrierUDP, down: wire.CarrierUDP}, quic: managed}
	bundle.quicOnce.Do(func() {})
	bundle.Close()

	if _, err := flow.readPacket(context.Background(), nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("flow error after bundle close = %v, want net.ErrClosed", err)
	}
	select {
	case <-session.loopDone:
	case <-time.After(time.Second):
		t.Fatal("bundle close did not stop mux receive loop")
	}
	if active := raw.active.Load(); active != 0 {
		t.Fatalf("active ReceiveDatagram calls after bundle close = %d, want 0", active)
	}
}

type muxReadResult struct {
	payload []byte
	err     error
}

func readMuxPacket(flow *quicDatagramFlow, result chan<- muxReadResult) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payload, err := flow.readPacket(ctx, nil)
	result <- muxReadResult{payload: payload, err: err}
}

func assertMuxPayload(t *testing.T, result <-chan muxReadResult, want string) {
	t.Helper()
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("read packet: %v", got.err)
		}
		if string(got.payload) != want {
			t.Fatalf("payload = %q, want %q", got.payload, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for payload %q", want)
	}
}

func mustMuxFrames(t *testing.T, flowID uint64, packetID uint32, payload []byte, maxSize int) [][]byte {
	t.Helper()
	frames, err := wire.EncodeUDPDataFragments(flowID, packetID, payload, maxSize)
	if err != nil {
		t.Fatalf("EncodeUDPDataFragments: %v", err)
	}
	return frames
}

type muxTestReceive struct {
	data []byte
	err  error
}

type muxTestSession struct {
	receives       chan muxTestReceive
	receiveStarted chan struct{}
	startedOnce    sync.Once
	active         atomic.Int32
	maxConcurrent  atomic.Int32
}

func newMuxTestSession() *muxTestSession {
	return &muxTestSession{
		receives:       make(chan muxTestReceive, 32),
		receiveStarted: make(chan struct{}),
	}
}

func (s *muxTestSession) PrepareStream(context.Context) (quic.PreparedStream, error) {
	return nil, errors.New("test: unexpected PrepareStream")
}

func (s *muxTestSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	s.startedOnce.Do(func() { close(s.receiveStarted) })
	active := s.active.Add(1)
	for {
		maximum := s.maxConcurrent.Load()
		if active <= maximum || s.maxConcurrent.CompareAndSwap(maximum, active) {
			break
		}
	}
	defer s.active.Add(-1)
	select {
	case result := <-s.receives:
		return result.data, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *muxTestSession) CurrentMaxDatagramSize() int { return 1200 }
func (s *muxTestSession) SendDatagram([]byte) error   { return nil }
func (s *muxTestSession) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (s *muxTestSession) push(data []byte, err error) {
	s.receives <- muxTestReceive{data: data, err: err}
}

var _ carrier.QuicSession = (*muxTestSession)(nil)

type muxTestBackend struct {
	session carrier.QuicSession
	closed  atomic.Bool
}

func (b *muxTestBackend) SetSessionID(wire.SessionID) {}
func (b *muxTestBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	if b.closed.Load() {
		return nil, net.ErrClosed
	}
	return b.session, nil
}
func (b *muxTestBackend) InvalidateSession(carrier.QuicSession) {}
func (b *muxTestBackend) Close() error {
	b.closed.Store(true)
	return nil
}

var _ carrier.QuicBackend = (*muxTestBackend)(nil)
