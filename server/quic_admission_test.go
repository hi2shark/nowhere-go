package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

func TestServeQUICAdmissionLimitSkipsAuthentication(t *testing.T) {
	observer := &recordingObserver{}
	handler, _ := newQUICAdmissionTestHandler(t, Limits{
		MaxUnauthenticatedConnections: 1,
		MaxUnauthenticatedPerSource:   1,
	}, observer)
	source := &net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 1000}
	releaseTCP := holdTCPAdmission(t, handler, source)
	defer releaseTCP()

	conn := &fakeQuicConn{remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 2000}}
	err := handler.ServeQUIC(context.Background(), conn)
	assertQUICAdmissionRejected(t, err, conn, observer)
}

func TestServeQUICSharesAdmissionWithTCP(t *testing.T) {
	observer := &recordingObserver{}
	handler, _ := newQUICAdmissionTestHandler(t, Limits{
		MaxUnauthenticatedConnections: 1,
		MaxUnauthenticatedPerSource:   1,
	}, observer)
	releaseTCP := holdTCPAdmission(t, handler, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1000})
	defer releaseTCP()

	conn := &fakeQuicConn{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 2000}}
	err := handler.ServeQUIC(context.Background(), conn)
	assertQUICAdmissionRejected(t, err, conn, observer)
}

func TestServeQUICSharesPerSourceAccounting(t *testing.T) {
	observer := &recordingObserver{}
	handler, _ := newQUICAdmissionTestHandler(t, Limits{
		MaxUnauthenticatedConnections: 2,
		MaxUnauthenticatedPerSource:   1,
	}, observer)
	releaseTCP := holdTCPAdmission(t, handler, &net.TCPAddr{IP: net.ParseIP("203.0.113.20"), Port: 1000})
	defer releaseTCP()

	conn := &fakeQuicConn{remote: &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 2000}}
	err := handler.ServeQUIC(context.Background(), conn)
	assertQUICAdmissionRejected(t, err, conn, observer)
}

func TestServeQUICReleasesAdmissionAfterAuthSuccess(t *testing.T) {
	handler, config := newQUICAdmissionTestHandler(t, Limits{
		MaxUnauthenticatedConnections: 1,
		MaxUnauthenticatedPerSource:   1,
	}, nil)
	frame, err := wire.MakeAuthFrameWithSession("secret", config.EffectiveSpec(), wire.SessionID{1})
	if err != nil {
		t.Fatal(err)
	}
	conn := &fakeQuicConn{
		stream: &fakeQuicStream{reader: bytes.NewReader(frame)},
		remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.30"), Port: 3000},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- handler.ServeQUIC(ctx, conn)
	}()

	waitForTestCondition(t, time.Second, func() bool {
		return conn.acceptStreamCalls.Load() >= 2
	}, "QUIC session did not reach the post-auth AcceptStream")
	select {
	case err := <-done:
		t.Fatalf("ServeQUIC returned while authenticated session should be blocked: %v", err)
	default:
	}
	if got := handler.admission.active(); got != 0 {
		t.Fatalf("admission active after QUIC auth success=%d want 0", got)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeQUIC after cancellation=%v want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ServeQUIC did not stop after cancellation")
	}
}

func TestServeQUICReleasesAdmissionAfterAuthFailure(t *testing.T) {
	observer := &recordingObserver{}
	handler, _ := newQUICAdmissionTestHandler(t, Limits{
		MaxUnauthenticatedConnections: 1,
		MaxUnauthenticatedPerSource:   1,
	}, observer)
	conn := &fakeQuicConn{
		stream: &fakeQuicStream{reader: bytes.NewReader([]byte{0})},
		remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.40"), Port: 4000},
	}

	start := time.Now()
	err := handler.ServeQUIC(context.Background(), conn)
	if err == nil {
		t.Fatal("invalid QUIC authentication succeeded")
	}
	if elapsed := time.Since(start); elapsed < 10*time.Millisecond {
		t.Fatalf("QUIC auth failure returned before deadline: %v", elapsed)
	}
	if got := handler.admission.active(); got != 0 {
		t.Fatalf("admission active after QUIC auth failure=%d want 0", got)
	}
	if got := conn.closeWithErrorCalls.Load(); got != 1 {
		t.Fatalf("CloseWithError calls=%d want 1", got)
	}
	if !observer.hasCode("auth_failed") {
		t.Fatal("missing auth_failed event")
	}
}

func newQUICAdmissionTestHandler(t *testing.T, limits Limits, observer *recordingObserver) (*Handler, *Config) {
	t.Helper()
	config, err := NewConfig(ConfigOptions{
		Password: "secret",
		Networks: []Network{NetworkTCP, NetworkUDP},
		Timeouts: Timeouts{Auth: 15 * time.Millisecond, TLSHandshake: time.Second},
		Limits:   limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}, Observer: observer})
	if err != nil {
		t.Fatal(err)
	}
	handler.randRead = func([]byte) (int, error) { return 0, errors.New("deterministic auth deadline") }
	return handler, config
}

func holdTCPAdmission(t *testing.T, handler *Handler, source net.Addr) func() {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	started := make(chan struct{})
	unblock := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- handler.ServeTCP(context.Background(), serverConn, source, func(context.Context, net.Conn) (net.Conn, error) {
			close(started)
			<-unblock
			return nil, errors.New("test handshake released")
		}, nil)
	}()

	var once sync.Once
	release := func() {
		once.Do(func() {
			close(unblock)
			_ = clientConn.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Errorf("blocked TCP admission did not stop")
			}
		})
	}
	t.Cleanup(release)

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("TCP handshaker did not start")
	}
	if got := handler.admission.active(); got != 1 {
		t.Fatalf("TCP connection admission active=%d want 1", got)
	}
	return release
}

func assertQUICAdmissionRejected(t *testing.T, err error, conn *fakeQuicConn, observer *recordingObserver) {
	t.Helper()
	if got := conn.acceptStreamCalls.Load(); got != 0 {
		t.Errorf("AcceptStream calls=%d want 0", got)
	}
	if got := conn.receiveDatagramCalls.Load(); got != 0 {
		t.Errorf("ReceiveDatagram calls=%d want 0", got)
	}
	if !errors.Is(err, ErrAdmissionLimit) {
		t.Errorf("ServeQUIC error=%v want ErrAdmissionLimit", err)
	}
	if !IsReported(err) {
		t.Errorf("admission rejection should be reported: %v", err)
	}
	if got := conn.closeWithErrorCalls.Load(); got != 1 {
		t.Errorf("CloseWithError calls=%d want 1", got)
	}
	code, message := conn.lastCloseWithError()
	if code != uint64(wire.CloseErrCodeOK) || message != "" {
		t.Errorf("CloseWithError=(%d, %q) want (%d, empty)", code, message, wire.CloseErrCodeOK)
	}
	if !observer.hasCode("admission_limited") {
		t.Error("missing admission_limited event")
	}
	if observer.hasCode("auth_failed") {
		t.Error("admission rejection emitted auth_failed")
	}
}

func waitForTestCondition(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(message)
}
