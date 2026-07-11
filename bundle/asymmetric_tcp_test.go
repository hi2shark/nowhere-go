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
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestAsymmetricOpenTCPCancelsOtherHalfOnFailure(t *testing.T) {
	spec := mustNowhereSpec(t)
	tcpDialer := newPipeTCPDialer()
	quic := &failPrepareQuic{}
	tcpConfig, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address: "127.0.0.1:1", Spec: spec, Key: "k", Dialer: tcpDialer, TLSDialer: passthroughTLSDialer{},
	})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	bundle, err := NewCarrierBundle(BundleOptions{
		QUIC: quic, TCP: tcpConfig, Up: wire.CarrierTCP, Down: wire.CarrierUDP,
	})
	if err != nil {
		t.Fatalf("NewCarrierBundle: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := bundle.AsymmetricOpenTCP(ctx, "example.com:443")
	elapsed := time.Since(start)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatalf("AsymmetricOpenTCP succeeded; want failure")
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("AsymmetricOpenTCP waited %s; want fast failure after QUIC prepare errors", elapsed)
	}
	select {
	case <-tcpDialer.closed:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("prepared TCP half was not closed after QUIC prepare failed")
	}
}

func TestSplicedConnForwardsDirectionalDeadlines(t *testing.T) {
	reader := &deadlineRecorderConn{}
	writer := &deadlineRecorderConn{}
	conn := &splicedConn{
		reader: reader,
		writer: writer,
		closer: []io.Closer{reader, writer},
		remote: dummyAddr("remote"),
		local:  dummyAddr("local"),
	}

	readAt := time.Unix(10, 0)
	if err := conn.SetReadDeadline(readAt); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if got := reader.readDeadline; !got.Equal(readAt) {
		t.Fatalf("reader read deadline = %v, want %v", got, readAt)
	}
	if !writer.readDeadline.IsZero() || !writer.writeDeadline.IsZero() {
		t.Fatalf("SetReadDeadline touched writer deadlines: read=%v write=%v", writer.readDeadline, writer.writeDeadline)
	}

	writeAt := time.Unix(20, 0)
	if err := conn.SetWriteDeadline(writeAt); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if got := writer.writeDeadline; !got.Equal(writeAt) {
		t.Fatalf("writer write deadline = %v, want %v", got, writeAt)
	}
	if got := reader.readDeadline; !got.Equal(readAt) {
		t.Fatalf("SetWriteDeadline changed reader read deadline = %v, want %v", got, readAt)
	}

	fullAt := time.Unix(30, 0)
	if err := conn.SetDeadline(fullAt); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if got := reader.readDeadline; !got.Equal(fullAt) {
		t.Fatalf("reader read deadline after SetDeadline = %v, want %v", got, fullAt)
	}
	if got := writer.writeDeadline; !got.Equal(fullAt) {
		t.Fatalf("writer write deadline after SetDeadline = %v, want %v", got, fullAt)
	}
}

func TestAsymmetricPacketConnForwardsUOTDeadlines(t *testing.T) {
	uplink := &deadlineRecorderConn{}
	downlink := &deadlineRecorderConn{}
	pc := &asymmetricPacketConn{
		uplink:   &uotLaneUplink{raw: uplink},
		downlink: &uotLaneDownlink{raw: downlink},
	}

	readAt := time.Unix(40, 0)
	if err := pc.SetReadDeadline(readAt); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if got := downlink.readDeadline; !got.Equal(readAt) {
		t.Fatalf("downlink read deadline = %v, want %v", got, readAt)
	}
	if !uplink.readDeadline.IsZero() || !uplink.writeDeadline.IsZero() {
		t.Fatalf("SetReadDeadline touched uplink deadlines: read=%v write=%v", uplink.readDeadline, uplink.writeDeadline)
	}

	writeAt := time.Unix(50, 0)
	if err := pc.SetWriteDeadline(writeAt); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if got := uplink.writeDeadline; !got.Equal(writeAt) {
		t.Fatalf("uplink write deadline = %v, want %v", got, writeAt)
	}
	if got := downlink.readDeadline; !got.Equal(readAt) {
		t.Fatalf("SetWriteDeadline changed downlink read deadline = %v, want %v", got, readAt)
	}

	fullAt := time.Unix(60, 0)
	if err := pc.SetDeadline(fullAt); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if got := downlink.readDeadline; !got.Equal(fullAt) {
		t.Fatalf("downlink read deadline after SetDeadline = %v, want %v", got, fullAt)
	}
	if got := uplink.writeDeadline; !got.Equal(fullAt) {
		t.Fatalf("uplink write deadline after SetDeadline = %v, want %v", got, fullAt)
	}
}

func mustNowhereSpec(t *testing.T) *wire.EffectiveSpec {
	t.Helper()
	spec, err := wire.BuildEffectiveSpec("k", "auto", "now/1")
	if err != nil {
		t.Fatalf("BuildEffectiveSpec: %v", err)
	}
	return spec
}

type blockingTCPDialer struct {
	started chan struct{}
	done    chan struct{}
	once    sync.Once
}

func newBlockingTCPDialer() *blockingTCPDialer {
	return &blockingTCPDialer{started: make(chan struct{}), done: make(chan struct{})}
}

func (d *blockingTCPDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.once.Do(func() { close(d.started) })
	defer close(d.done)
	<-ctx.Done()
	return nil, ctx.Err()
}

type pipeTCPDialer struct {
	closed chan struct{}
	once   sync.Once
}

func newPipeTCPDialer() *pipeTCPDialer {
	return &pipeTCPDialer{closed: make(chan struct{})}
}

func (d *pipeTCPDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		buf := make([]byte, 4096)
		for {
			if _, err := c2.Read(buf); err != nil {
				d.once.Do(func() { close(d.closed) })
				return
			}
		}
	}()
	return c1, nil
}

type passthroughTLSDialer struct{}

func (passthroughTLSDialer) DialTLSConn(ctx context.Context, c net.Conn) (net.Conn, error) {
	return c, nil
}

type deadlineRecorderConn struct {
	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *deadlineRecorderConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *deadlineRecorderConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *deadlineRecorderConn) Close() error                { return nil }
func (c *deadlineRecorderConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (c *deadlineRecorderConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }
func (c *deadlineRecorderConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}
func (c *deadlineRecorderConn) SetReadDeadline(t time.Time) error  { c.readDeadline = t; return nil }
func (c *deadlineRecorderConn) SetWriteDeadline(t time.Time) error { c.writeDeadline = t; return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

// failAfterWaitQuic fails OpenFlowStream after wait is signaled (TCP half started).
type failAfterWaitQuic struct {
	wait <-chan struct{}
	id   wire.SessionID
}

func (q *failAfterWaitQuic) SetSessionID(id wire.SessionID) { q.id = id }
func (q *failAfterWaitQuic) OpenTCP(context.Context, string) (net.Conn, error) {
	return nil, errors.New("test: unexpected OpenTCP")
}
func (q *failAfterWaitQuic) OpenFlowStream(ctx context.Context, _ string, _ wire.FlowHeader) (net.Conn, error) {
	select {
	case <-q.wait:
		return nil, errors.New("test: quic half failed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (q *failAfterWaitQuic) PrepareFlowStream(ctx context.Context) (quic.PreparedFlowStream, error) {
	select {
	case <-q.wait:
		return nil, errors.New("test: quic prepare failed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (q *failAfterWaitQuic) OpenUDP(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("test: unexpected OpenUDP")
}
func (q *failAfterWaitQuic) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return nil, errors.New("test: unexpected AcquireSession")
}
func (q *failAfterWaitQuic) InvalidateSession(carrier.QuicSession) {}
func (q *failAfterWaitQuic) Close()                                {}

type failPrepareQuic struct {
	id wire.SessionID
}

func (q *failPrepareQuic) SetSessionID(id wire.SessionID) { q.id = id }
func (q *failPrepareQuic) OpenTCP(context.Context, string) (net.Conn, error) {
	return nil, errors.New("test: unexpected OpenTCP")
}
func (q *failPrepareQuic) OpenFlowStream(context.Context, string, wire.FlowHeader) (net.Conn, error) {
	return nil, errors.New("test: unexpected OpenFlowStream")
}
func (q *failPrepareQuic) PrepareFlowStream(context.Context) (quic.PreparedFlowStream, error) {
	return nil, errors.New("test: quic prepare failed")
}
func (q *failPrepareQuic) OpenUDP(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("test: unexpected OpenUDP")
}
func (q *failPrepareQuic) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return nil, errors.New("test: unexpected AcquireSession")
}
func (q *failPrepareQuic) InvalidateSession(carrier.QuicSession) {}
func (q *failPrepareQuic) Close()                                {}

type recordingPreparedStream struct {
	committed chan struct{}
	closed    chan struct{}
	failCommit bool
	once      sync.Once
}

func (p *recordingPreparedStream) Commit(context.Context, string, wire.FlowHeader) (net.Conn, error) {
	if p.failCommit {
		p.once.Do(func() { close(p.closed) })
		return nil, errors.New("test: commit failed")
	}
	c1, c2 := net.Pipe()
	go func() { _ = c2.Close() }()
	p.once.Do(func() { close(p.committed) })
	return c1, nil
}

func (p *recordingPreparedStream) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

type prepareOKQuic struct {
	id       wire.SessionID
	prepared *recordingPreparedStream
}

func (q *prepareOKQuic) SetSessionID(id wire.SessionID) { q.id = id }
func (q *prepareOKQuic) OpenTCP(context.Context, string) (net.Conn, error) {
	return nil, errors.New("test: unexpected OpenTCP")
}
func (q *prepareOKQuic) OpenFlowStream(context.Context, string, wire.FlowHeader) (net.Conn, error) {
	return nil, errors.New("test: unexpected OpenFlowStream")
}
func (q *prepareOKQuic) PrepareFlowStream(context.Context) (quic.PreparedFlowStream, error) {
	if q.prepared == nil {
		q.prepared = &recordingPreparedStream{committed: make(chan struct{}), closed: make(chan struct{})}
	}
	return q.prepared, nil
}
func (q *prepareOKQuic) OpenUDP(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("test: unexpected OpenUDP")
}
func (q *prepareOKQuic) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return nil, errors.New("test: unexpected AcquireSession")
}
func (q *prepareOKQuic) InvalidateSession(carrier.QuicSession) {}
func (q *prepareOKQuic) Close()                                {}

func TestAsymmetricOpenTCPClosesTCPOnQUICCommitFailure(t *testing.T) {
	spec := mustNowhereSpec(t)
	tcpDialer := newPipeTCPDialer()
	quic := &prepareOKQuic{prepared: &recordingPreparedStream{
		committed:  make(chan struct{}),
		closed:     make(chan struct{}),
		failCommit: true,
	}}
	tcpConfig, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address: "127.0.0.1:1", Spec: spec, Key: "k", Dialer: tcpDialer, TLSDialer: passthroughTLSDialer{},
	})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	bundle, err := NewCarrierBundle(BundleOptions{
		QUIC: quic, TCP: tcpConfig, Up: wire.CarrierTCP, Down: wire.CarrierUDP,
	})
	if err != nil {
		t.Fatalf("NewCarrierBundle: %v", err)
	}
	conn, err := bundle.AsymmetricOpenTCP(context.Background(), "example.com:443")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("expected commit failure")
	}
	select {
	case <-tcpDialer.closed:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("TCP half not closed after QUIC commit failure")
	}
}

func TestAsymmetricOpenTCPNoFLOWBeforeBothPrepared(t *testing.T) {
	spec := mustNowhereSpec(t)
	var mu sync.Mutex
	var sawRequest bool
	tcpDialer := &hookPipeDialer{onWrite: func(p []byte) {
		mu.Lock()
		defer mu.Unlock()
		if len(p) > 0 && p[0] == wire.FlowFrameMagic {
			sawRequest = true
		}
	}}
	quicReady := make(chan struct{})
	quic := &gatePrepareQuic{ready: quicReady}
	tcpConfig, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address: "127.0.0.1:1", Spec: spec, Key: "k", Dialer: tcpDialer, TLSDialer: passthroughTLSDialer{},
	})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	bundle, err := NewCarrierBundle(BundleOptions{
		QUIC: quic, TCP: tcpConfig, Up: wire.CarrierTCP, Down: wire.CarrierUDP,
	})
	if err != nil {
		t.Fatalf("NewCarrierBundle: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		conn, err := bundle.AsymmetricOpenTCP(context.Background(), "example.com:443")
		if conn != nil {
			_ = conn.Close()
		}
		errCh <- err
	}()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if tcpDialer.prepared.Load() {
			break
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	leaked := sawRequest
	mu.Unlock()
	if leaked {
		t.Fatal("FLOW frame written before QUIC prepare completed")
	}
	close(quicReady)
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("AsymmetricOpenTCP: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("AsymmetricOpenTCP timed out")
	}
}

type hookPipeDialer struct {
	prepared atomic.Bool
	onWrite  func([]byte)
}

func (d *hookPipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		buf := make([]byte, 4096)
		for {
			n, err := c2.Read(buf)
			if n > 0 && d.onWrite != nil {
				d.onWrite(buf[:n])
			}
			if err != nil {
				return
			}
			d.prepared.Store(true)
		}
	}()
	return c1, nil
}

type gatePrepareQuic struct {
	ready <-chan struct{}
	id    wire.SessionID
}

func (q *gatePrepareQuic) SetSessionID(id wire.SessionID) { q.id = id }
func (q *gatePrepareQuic) OpenTCP(context.Context, string) (net.Conn, error) {
	return nil, errors.New("test: unexpected OpenTCP")
}
func (q *gatePrepareQuic) OpenFlowStream(context.Context, string, wire.FlowHeader) (net.Conn, error) {
	return nil, errors.New("test: unexpected OpenFlowStream")
}
func (q *gatePrepareQuic) PrepareFlowStream(ctx context.Context) (quic.PreparedFlowStream, error) {
	select {
	case <-q.ready:
		return &recordingPreparedStream{committed: make(chan struct{}), closed: make(chan struct{})}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (q *gatePrepareQuic) OpenUDP(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("test: unexpected OpenUDP")
}
func (q *gatePrepareQuic) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return nil, errors.New("test: unexpected AcquireSession")
}
func (q *gatePrepareQuic) InvalidateSession(carrier.QuicSession) {}
func (q *gatePrepareQuic) Close()                                {}
