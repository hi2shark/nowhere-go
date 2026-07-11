//go:build !go1.24

package bundle

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestCarrierBundleSessionIDRandomErrorPersists(t *testing.T) {
	oldReader := rand.Reader
	wantErr := errors.New("test: random failed")
	rand.Reader = errReader{fill: 0x7f, err: wantErr}
	t.Cleanup(func() { rand.Reader = oldReader })

	bundle, err := NewCarrierBundle(BundleOptions{
		QUIC: &stubQuicBackend{},
		TCP:  testBundleTCPConfig(t),
		Up:   wire.CarrierTCP,
		Down: wire.CarrierUDP,
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("NewCarrierBundle = %v, %v; want error %v", bundle, err, wantErr)
	}
}

type errReader struct {
	fill byte
	err  error
}

func (r errReader) Read(p []byte) (int, error) {
	if len(p) > 0 {
		p[0] = r.fill
		return 1, r.err
	}
	return 0, r.err
}

var _ io.Reader = errReader{}

func testBundleTCPConfig(t *testing.T) *tcptls.Config {
	t.Helper()
	config, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address: "127.0.0.1:1", Spec: mustNowhereSpec(t), Key: "k",
		Dialer: newBlockingTCPDialer(), TLSDialer: passthroughTLSDialer{},
	})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	return config
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

// stubQuicBackend is a no-op backend for config-only tests.
type stubQuicBackend struct {
	id wire.SessionID
}

func (s *stubQuicBackend) SetSessionID(id wire.SessionID) { s.id = id }
func (s *stubQuicBackend) OpenTCP(context.Context, string) (net.Conn, error) {
	return nil, errors.New("stub: OpenTCP")
}
func (s *stubQuicBackend) OpenFlowStream(context.Context, string, wire.FlowHeader) (net.Conn, error) {
	return nil, errors.New("stub: OpenFlowStream")
}
func (s *stubQuicBackend) PrepareFlowStream(context.Context) (quic.PreparedFlowStream, error) {
	return nil, errors.New("stub: PrepareFlowStream")
}
func (s *stubQuicBackend) OpenUDP(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("stub: OpenUDP")
}
func (s *stubQuicBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return nil, errors.New("stub: AcquireSession")
}
func (s *stubQuicBackend) InvalidateSession(carrier.QuicSession) {}
func (s *stubQuicBackend) Close()                                {}
