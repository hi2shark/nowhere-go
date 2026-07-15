package bundle

import (
	"bytes"
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

func TestPacketConnCloseUnblocksSymmetricUOTReadAndWrite(t *testing.T) {
	conn := newTask5BlockingConn()
	t.Cleanup(conn.release)
	pc := newUOTPacketConn(conn, &net.UDPAddr{})

	readResult := make(chan error, 1)
	go func() {
		_, _, err := pc.ReadFrom(make([]byte, 16))
		readResult <- err
	}()
	writeResult := make(chan error, 1)
	go func() {
		_, err := pc.WriteTo([]byte("blocked"), nil)
		writeResult <- err
	}()
	task5AwaitSignal(t, conn.readStarted, "UoT read")
	task5AwaitSignal(t, conn.writeStarted, "UoT write")

	closeResult := make(chan error, 1)
	go func() { closeResult <- pc.Close() }()
	task5AwaitCloseResult(t, closeResult, "symmetric UoT Close")
	task5AwaitClosedError(t, readResult, "symmetric UoT ReadFrom")
	task5AwaitClosedError(t, writeResult, "symmetric UoT WriteTo")
	if got := conn.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
}

func TestUOTCloseWritesSingleTypedClose(t *testing.T) {
	for _, path := range []string{"symmetric", "mixed"} {
		t.Run(path, func(t *testing.T) {
			conn := &task5RecordingConn{}
			var closePacket func() error
			switch path {
			case "symmetric":
				pc := newUOTPacketConn(conn, &net.UDPAddr{})
				closePacket = pc.Close
			case "mixed":
				lane := &uotLaneUplink{raw: conn}
				closePacket = lane.ClosePacket
			}
			if err := closePacket(); err != nil {
				t.Fatalf("first Close: %v", err)
			}
			if err := closePacket(); err != nil {
				t.Fatalf("second Close: %v", err)
			}

			writes, closeCalls := conn.snapshot()
			if closeCalls != 1 {
				t.Fatalf("underlying Close calls = %d, want 1", closeCalls)
			}
			if len(writes) != 1 {
				t.Fatalf("UoT writes = %d, want one CLOSE", len(writes))
			}
			frame, err := wire.ReadUOTFrame(bytes.NewReader(writes[0]))
			if err != nil {
				t.Fatalf("ReadUOTFrame: %v", err)
			}
			if frame.Kind != wire.UOTFrameClose {
				t.Fatalf("frame kind = %d, want CLOSE", frame.Kind)
			}
		})
	}
}

func TestPacketConnCloseUnblocksBlockedQUICReadAndWrite(t *testing.T) {
	for _, path := range []string{"symmetric", "mixed"} {
		t.Run(path, func(t *testing.T) {
			raw := newTask5BlockingSendSession()
			backend := &task5BlockingSendBackend{session: raw}
			managed := newQUICMuxBackend(backend)
			t.Cleanup(func() {
				raw.release()
				_ = managed.Close()
			})
			sessionValue, err := managed.AcquireSession(context.Background())
			if err != nil {
				t.Fatalf("AcquireSession: %v", err)
			}

			const flowID = uint64(71)
			prepared := &quicPreparedStream{session: sessionValue, id: flowID}
			var pc net.PacketConn
			var mixedReadConn *task5BlockingConn
			switch path {
			case "symmetric":
				pc = newQUICPacketConn(prepared, nil, "example.com:53")
			case "mixed":
				mixedReadConn = newTask5BlockingConn()
				t.Cleanup(mixedReadConn.release)
				pc = &asymmetricPacketConn{
					dest:     "example.com:53",
					uplink:   &quicLaneUplink{prep: newQUICSendHandle(prepared, flowID), flowID: flowID},
					downlink: &uotLaneDownlink{raw: mixedReadConn},
				}
			}

			readResult := make(chan error, 1)
			go func() {
				_, _, err := pc.ReadFrom(make([]byte, 16))
				readResult <- err
			}()
			if mixedReadConn != nil {
				task5AwaitSignal(t, mixedReadConn.readStarted, "mixed downlink read")
			}
			writeResult := make(chan error, 1)
			go func() {
				_, err := pc.WriteTo([]byte("blocked"), nil)
				writeResult <- err
			}()
			task5AwaitSignal(t, raw.sendStarted, "QUIC SendDatagram")

			closeResult := make(chan error, 1)
			go func() { closeResult <- pc.Close() }()
			task5AwaitCloseResult(t, closeResult, path+" QUIC Close")
			task5AwaitClosedError(t, readResult, path+" QUIC ReadFrom")
			task5AwaitClosedError(t, writeResult, path+" QUIC WriteTo")
			if got := backend.closeCalls.Load(); got != 0 {
				t.Fatalf("flow Close closed shared backend %d times", got)
			}

			raw.release()
			const nextFlowID = uint64(72)
			nextPrepared := &quicPreparedStream{session: sessionValue, id: nextFlowID}
			next := &quicLaneUplink{prep: newQUICSendHandle(nextPrepared, nextFlowID), flowID: nextFlowID}
			nextResult := make(chan error, 1)
			go func() {
				_, err := next.WritePacket([]byte("next"))
				nextResult <- err
			}()
			select {
			case err := <-nextResult:
				if err != nil {
					t.Fatalf("next flow WritePacket: %v", err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("next flow remained blocked after host send resumed")
			}
		})
	}
}

func TestQUICSessionCloseUsesBackendToReleaseBlockedSend(t *testing.T) {
	raw := newTask5BlockingSendSession()
	backend := &task5BlockingSendBackend{session: raw}
	managed := newQUICMuxBackend(backend)
	t.Cleanup(func() {
		raw.release()
		_ = managed.Close()
	})
	sessionValue, err := managed.AcquireSession(context.Background())
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	const flowID = uint64(81)
	prepared := &quicPreparedStream{session: sessionValue, id: flowID}
	lane := &quicLaneUplink{prep: newQUICSendHandle(prepared, flowID), flowID: flowID}
	writeResult := make(chan error, 1)
	go func() {
		_, err := lane.WritePacket([]byte("blocked"))
		writeResult <- err
	}()
	task5AwaitSignal(t, raw.sendStarted, "QUIC SendDatagram")

	closeResult := make(chan error, 1)
	go func() { closeResult <- managed.Close() }()
	task5AwaitCloseResult(t, closeResult, "QUIC session Close")
	task5AwaitClosedError(t, writeResult, "QUIC session WritePacket")
	if got := backend.closeCalls.Load(); got != 1 {
		t.Fatalf("backend Close calls = %d, want 1", got)
	}
}

func task5AwaitSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("timed out waiting for blocked %s", operation)
	}
}

func task5AwaitCloseResult(t *testing.T, result <-chan error, operation string) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("%s did not return while I/O was blocked", operation)
	}
}

func task5AwaitClosedError(t *testing.T, result <-chan error, operation string) {
	t.Helper()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("%s error = %v, want net.ErrClosed", operation, err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("%s remained blocked after Close", operation)
	}
}

type task5BlockingConn struct {
	closed       chan struct{}
	readStarted  chan struct{}
	writeStarted chan struct{}
	readOnce     sync.Once
	writeOnce    sync.Once
	closeOnce    sync.Once
	closeCalls   atomic.Int32
}

func newTask5BlockingConn() *task5BlockingConn {
	return &task5BlockingConn{
		closed:       make(chan struct{}),
		readStarted:  make(chan struct{}),
		writeStarted: make(chan struct{}),
	}
}

func (c *task5BlockingConn) Read([]byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *task5BlockingConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *task5BlockingConn) Close() error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *task5BlockingConn) release()                       { _ = c.Close() }
func (*task5BlockingConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*task5BlockingConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*task5BlockingConn) SetDeadline(time.Time) error      { return nil }
func (*task5BlockingConn) SetReadDeadline(time.Time) error  { return nil }
func (*task5BlockingConn) SetWriteDeadline(time.Time) error { return nil }

type task5RecordingConn struct {
	mu         sync.Mutex
	writes     [][]byte
	closeCalls int
}

func (*task5RecordingConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *task5RecordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return len(p), nil
}
func (c *task5RecordingConn) Close() error {
	c.mu.Lock()
	c.closeCalls++
	c.mu.Unlock()
	return nil
}
func (*task5RecordingConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*task5RecordingConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*task5RecordingConn) SetDeadline(time.Time) error      { return nil }
func (*task5RecordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*task5RecordingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *task5RecordingConn) snapshot() ([][]byte, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	writes := make([][]byte, len(c.writes))
	for i, write := range c.writes {
		writes[i] = append([]byte(nil), write...)
	}
	return writes, c.closeCalls
}

type task5BlockingSendSession struct {
	sendStarted chan struct{}
	releaseSend chan struct{}
	startedOnce sync.Once
	releaseOnce sync.Once
}

func newTask5BlockingSendSession() *task5BlockingSendSession {
	return &task5BlockingSendSession{
		sendStarted: make(chan struct{}),
		releaseSend: make(chan struct{}),
	}
}

func (*task5BlockingSendSession) PrepareStream(context.Context) (quic.PreparedStream, error) {
	return nil, errors.New("test: unexpected PrepareStream")
}
func (*task5BlockingSendSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*task5BlockingSendSession) CurrentMaxDatagramSize() int { return nowuDataHeaderLen + 64 }
func (s *task5BlockingSendSession) SendDatagram([]byte) error {
	s.startedOnce.Do(func() { close(s.sendStarted) })
	<-s.releaseSend
	return nil
}
func (*task5BlockingSendSession) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (s *task5BlockingSendSession) release() {
	s.releaseOnce.Do(func() { close(s.releaseSend) })
}

var _ carrier.QuicSession = (*task5BlockingSendSession)(nil)

type task5BlockingSendBackend struct {
	session    carrier.QuicSession
	closeCalls atomic.Int32
}

func (*task5BlockingSendBackend) SetSessionID(wire.SessionID) {}
func (b *task5BlockingSendBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return b.session, nil
}
func (*task5BlockingSendBackend) InvalidateSession(carrier.QuicSession) {}
func (b *task5BlockingSendBackend) Close() error {
	b.closeCalls.Add(1)
	if session, ok := b.session.(*task5BlockingSendSession); ok {
		session.release()
	}
	return nil
}

var _ carrier.QuicBackend = (*task5BlockingSendBackend)(nil)
