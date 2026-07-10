package bundle

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestAsymmetricOpenTCPCancelsOtherHalfOnFailure(t *testing.T) {
	spec := mustNowhereSpec(t)
	tcpDialer := newBlockingTCPDialer()
	quic := &failAfterWaitQuic{wait: tcpDialer.started}
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
	if elapsed > 150*time.Millisecond {
		t.Fatalf("AsymmetricOpenTCP waited %s; want fast failure after other half errors", elapsed)
	}
	select {
	case <-tcpDialer.done:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("blocking TCP half was not canceled after the UDP half failed")
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
func (q *failAfterWaitQuic) OpenUDP(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("test: unexpected OpenUDP")
}
func (q *failAfterWaitQuic) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return nil, errors.New("test: unexpected AcquireSession")
}
func (q *failAfterWaitQuic) InvalidateSession(carrier.QuicSession) {}
func (q *failAfterWaitQuic) Close()                                {}
