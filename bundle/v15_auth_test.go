package bundle

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/hi2shark/nowhere-go/carrier"
	nquic "github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestBundleOwnsQUICAuthAndWritesAuthOnlyFIN(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	raw := &v15AuthSession{}
	backend := &v15AuthBackend{session: raw}
	b := newV15QUICOnlyBundle(t, credentials, backend)
	defer b.Close()

	quic, err := b.quicClient()
	if err != nil {
		t.Fatalf("quicClient: %v", err)
	}
	if _, err := quic.AcquireSession(context.Background()); err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	if backend.acquires != 1 {
		t.Fatalf("backend acquire count = %d, want 1", backend.acquires)
	}
	if raw.stream.commits != 1 || !raw.stream.finishWrite {
		t.Fatalf("auth commit = (%d, finish=%v), want one auth-only FIN", raw.stream.commits, raw.stream.finishWrite)
	}
	if len(raw.stream.setup) != wire.AuthFrameLen {
		t.Fatalf("auth bytes = %d, want %d", len(raw.stream.setup), wire.AuthFrameLen)
	}
	id, err := wire.ValidateAuthFrame(raw.stream.setup, credentials, wire.AuthTransportQUIC, raw.exporter)
	if err != nil {
		t.Fatalf("ValidateAuthFrame: %v", err)
	}
	wantID, err := b.SessionID()
	if err != nil {
		t.Fatal(err)
	}
	if id != wantID {
		t.Fatalf("auth session ID = %x, bundle ID = %x", id, wantID)
	}

	// Reacquiring the same physical connection must not ask the host to
	// authenticate again.  The Session ID never leaves the injected backend.
	if _, err := quic.AcquireSession(context.Background()); err != nil {
		t.Fatalf("second AcquireSession: %v", err)
	}
	if raw.stream.commits != 1 {
		t.Fatalf("auth commits after reuse = %d, want 1", raw.stream.commits)
	}
}

func TestBundleInvalidatesQUICSessionWhenExporterFails(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	raw := &v15AuthSession{exporterErr: errors.New("exporter unavailable")}
	backend := &v15AuthBackend{session: raw}
	b := newV15QUICOnlyBundle(t, credentials, backend)
	defer b.Close()

	quic, err := b.quicClient()
	if err != nil {
		t.Fatalf("quicClient: %v", err)
	}
	if _, err := quic.AcquireSession(context.Background()); !errors.Is(err, raw.exporterErr) {
		t.Fatalf("AcquireSession error = %v, want exporter error", err)
	}
	if backend.invalidated != raw {
		t.Fatal("failed authentication did not invalidate the physical session")
	}
	if raw.stream.commits != 0 {
		t.Fatalf("auth was written despite exporter failure: %d commits", raw.stream.commits)
	}
}

func newV15QUICOnlyBundle(t *testing.T, credentials *wire.Credentials, backend carrier.QuicBackend) *CarrierBundle {
	t.Helper()
	tcp, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address:     "portal.example:443",
		Credentials: credentials,
		Transport:   wire.AuthTransportTLSTCP,
		Dialer:      v15NoopTCPDialer{},
		TLSDialer:   v15NoopTLSDialer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCarrierBundle(BundleOptions{
		TCP: tcp, QUIC: backend, Up: wire.CarrierQUIC, Down: wire.CarrierQUIC,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type v15NoopTCPDialer struct{}

func (v15NoopTCPDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unused")
}

type v15NoopTLSDialer struct{}

func (v15NoopTLSDialer) DialTLSConn(context.Context, net.Conn) (wire.HandshakedConn, error) {
	return wire.HandshakedConn{}, errors.New("unused")
}

type v15AuthBackend struct {
	session     *v15AuthSession
	acquires    int
	invalidated carrier.QuicSession
}

func (b *v15AuthBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	b.acquires++
	return b.session, nil
}
func (b *v15AuthBackend) InvalidateSession(session carrier.QuicSession) { b.invalidated = session }
func (*v15AuthBackend) Close() error                                    { return nil }

type v15AuthSession struct {
	exporter    wire.TLSExporter
	exporterErr error
	stream      v15AuthPreparedStream
}

func (s *v15AuthSession) TLSExporter() (wire.TLSExporter, error) { return s.exporter, s.exporterErr }
func (s *v15AuthSession) PrepareStream(context.Context) (nquic.PreparedStream, error) {
	return &s.stream, nil
}
func (*v15AuthSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*v15AuthSession) CurrentMaxDatagramSize() int { return 1200 }
func (*v15AuthSession) SendDatagram([]byte) error   { return nil }
func (*v15AuthSession) LocalAddr() net.Addr         { return &net.UDPAddr{} }

type v15AuthPreparedStream struct {
	mu          sync.Mutex
	setup       []byte
	finishWrite bool
	commits     int
}

func (s *v15AuthPreparedStream) Commit(_ context.Context, setup []byte, finishWrite bool) (net.Conn, error) {
	s.mu.Lock()
	s.setup = append(s.setup[:0], setup...)
	s.finishWrite = finishWrite
	s.commits++
	s.mu.Unlock()
	return nil, nil
}
func (*v15AuthPreparedStream) Close() error { return nil }

var _ carrier.QuicBackend = (*v15AuthBackend)(nil)
var _ carrier.QuicSession = (*v15AuthSession)(nil)
