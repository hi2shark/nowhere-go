package bundle

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestQUICDatagramReadDeadlineUnblocksBlockedRead(t *testing.T) {
	for _, path := range []string{"udp-udp", "tcp-udp"} {
		t.Run(path, func(t *testing.T) {
			raw := newDeadlineBlockingSession()
			backend := &deadlineBlockingBackend{session: raw}
			managed := newQUICMuxBackend(backend)
			t.Cleanup(func() { _ = managed.Close() })
			sessionValue, err := managed.AcquireSession(context.Background())
			if err != nil {
				t.Fatalf("AcquireSession: %v", err)
			}
			const flowID = uint64(201)
			prepared := &quicPreparedStream{session: sessionValue, id: flowID}

			var packetConn net.PacketConn
			switch path {
			case "udp-udp":
				packetConn = newQUICPacketConn(prepared, nil, "example.com:53")
			case "tcp-udp":
				handle, err := newQUICDatagramHandle(prepared, flowID)
				if err != nil {
					t.Fatalf("newQUICDatagramHandle: %v", err)
				}
				packetConn = &asymmetricPacketConn{
					dest:     "example.com:53",
					uplink:   deadlineNoopUplink{},
					downlink: &quicLaneDownlink{prep: handle, flowID: flowID},
				}
			}
			awaitDeadlineSignal(t, raw.receiveStarted, "QUIC receive loop")

			started := make(chan struct{})
			result := make(chan error, 1)
			go func() {
				close(started)
				_, _, err := packetConn.ReadFrom(make([]byte, 16))
				result <- err
			}()
			awaitDeadlineSignal(t, started, "ReadFrom start")
			time.Sleep(10 * time.Millisecond)
			if err := packetConn.SetReadDeadline(time.Now()); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			assertDeadlineResult(t, result, path+" ReadFrom")
		})
	}
}

func TestQUICDatagramWriteDeadlineInvalidatesBlockedSend(t *testing.T) {
	for _, path := range []string{"udp-udp", "udp-tcp"} {
		t.Run(path, func(t *testing.T) {
			raw := newDeadlineBlockingSession()
			backend := &deadlineBlockingBackend{session: raw}
			managed := newQUICMuxBackend(backend)
			t.Cleanup(func() { _ = managed.Close() })
			sessionValue, err := managed.AcquireSession(context.Background())
			if err != nil {
				t.Fatalf("AcquireSession: %v", err)
			}
			const flowID = uint64(202)
			prepared := &quicPreparedStream{session: sessionValue, id: flowID}

			var packetConn net.PacketConn
			switch path {
			case "udp-udp":
				packetConn = newQUICPacketConn(prepared, nil, "example.com:53")
			case "udp-tcp":
				packetConn = &asymmetricPacketConn{
					dest:     "example.com:53",
					uplink:   &quicLaneUplink{prep: newQUICSendHandle(prepared, flowID), flowID: flowID},
					downlink: deadlineNoopDownlink{},
				}
			}

			result := make(chan error, 1)
			go func() {
				_, err := packetConn.WriteTo([]byte("blocked"), nil)
				result <- err
			}()
			awaitDeadlineSignal(t, raw.sendStarted, "native SendDatagram")
			if err := packetConn.SetWriteDeadline(time.Now()); err != nil {
				t.Fatalf("SetWriteDeadline: %v", err)
			}
			assertDeadlineResult(t, result, path+" WriteTo")
			if got := backend.invalidations.Load(); got != 1 {
				t.Fatalf("session invalidations = %d, want 1", got)
			}
		})
	}
}

func assertDeadlineResult(t *testing.T, result <-chan error, operation string) {
	t.Helper()
	select {
	case err := <-result:
		if err == nil {
			t.Fatalf("%s returned nil, want timeout", operation)
		}
		var netError net.Error
		if !errors.Is(err, os.ErrDeadlineExceeded) && (!errors.As(err, &netError) || !netError.Timeout()) {
			t.Fatalf("%s error = %v, want timeout-class error", operation, err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("%s remained blocked after deadline", operation)
	}
}

func awaitDeadlineSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

type deadlineNoopUplink struct{}

func (deadlineNoopUplink) WritePacket(p []byte) (int, error) { return len(p), nil }
func (deadlineNoopUplink) ClosePacket() error                { return nil }

type deadlineNoopDownlink struct{}

func (deadlineNoopDownlink) ReadPacket([]byte) (int, error) {
	return 0, errors.New("test: unexpected read")
}
func (deadlineNoopDownlink) ClosePacket() error { return nil }

type deadlineBlockingSession struct {
	receiveStarted chan struct{}
	sendStarted    chan struct{}
	sendRelease    chan struct{}
	receiveOnce    sync.Once
	sendOnce       sync.Once
	releaseOnce    sync.Once
	invalidated    atomic.Bool
}

func newDeadlineBlockingSession() *deadlineBlockingSession {
	return &deadlineBlockingSession{
		receiveStarted: make(chan struct{}),
		sendStarted:    make(chan struct{}),
		sendRelease:    make(chan struct{}),
	}
}

func (*deadlineBlockingSession) PrepareStream(context.Context) (quic.PreparedStream, error) {
	return nil, errors.New("test: unexpected PrepareStream")
}
func (s *deadlineBlockingSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	s.receiveOnce.Do(func() { close(s.receiveStarted) })
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*deadlineBlockingSession) CurrentMaxDatagramSize() int { return nowuDataHeaderLen + 64 }
func (s *deadlineBlockingSession) SendDatagram([]byte) error {
	s.sendOnce.Do(func() { close(s.sendStarted) })
	<-s.sendRelease
	if s.invalidated.Load() {
		return net.ErrClosed
	}
	return nil
}
func (*deadlineBlockingSession) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (s *deadlineBlockingSession) invalidate() {
	s.invalidated.Store(true)
	s.releaseOnce.Do(func() { close(s.sendRelease) })
}

type deadlineBlockingBackend struct {
	session       *deadlineBlockingSession
	invalidations atomic.Int32
}

func (*deadlineBlockingBackend) SetSessionID(wire.SessionID) {}
func (b *deadlineBlockingBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return b.session, nil
}
func (b *deadlineBlockingBackend) InvalidateSession(carrier.QuicSession) {
	b.invalidations.Add(1)
	b.session.invalidate()
}
func (b *deadlineBlockingBackend) Close() error {
	b.session.invalidate()
	return nil
}

var _ quic.Backend = (*deadlineBlockingBackend)(nil)
