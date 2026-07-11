package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/diagnostic"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestUnauthenticatedAdmissionGlobalAndPerSource(t *testing.T) {
	admission := newUnauthenticatedAdmission(3, 2)
	srcA := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}
	srcB := &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1}

	g1, ok := admission.tryAcquire(srcA)
	if !ok {
		t.Fatal("first acquire failed")
	}
	g2, ok := admission.tryAcquire(srcA)
	if !ok {
		t.Fatal("second acquire for same source failed")
	}
	if _, ok := admission.tryAcquire(srcA); ok {
		t.Fatal("per-source limit not enforced")
	}
	g3, ok := admission.tryAcquire(srcB)
	if !ok {
		t.Fatal("other source acquire failed")
	}
	if _, ok := admission.tryAcquire(srcB); ok {
		t.Fatal("global limit not enforced")
	}
	if got := admission.active(); got != 3 {
		t.Fatalf("active=%d want 3", got)
	}
	g1.Release()
	g2.Release()
	g2.Release() // idempotent
	if got := admission.active(); got != 1 {
		t.Fatalf("active after release=%d want 1", got)
	}
	g3.Release()
	if got := admission.active(); got != 0 {
		t.Fatalf("active after all released=%d want 0", got)
	}
}

func TestUnauthenticatedAdmissionGroupsIPv6By64(t *testing.T) {
	admission := newUnauthenticatedAdmission(8, 1)
	a := &net.TCPAddr{IP: net.ParseIP("2001:db8:1::1"), Port: 10}
	b := &net.TCPAddr{IP: net.ParseIP("2001:db8:1::2"), Port: 11}
	g, ok := admission.tryAcquire(a)
	if !ok {
		t.Fatal("first IPv6 acquire failed")
	}
	if _, ok := admission.tryAcquire(b); ok {
		t.Fatal("IPv6 /64 per-source limit not enforced")
	}
	g.Release()
	if _, ok := admission.tryAcquire(b); !ok {
		t.Fatal("acquire after release failed")
	}
}

func TestServeTCPAdmissionLimitClosesImmediately(t *testing.T) {
	config, err := NewConfig(ConfigOptions{
		Password: "secret",
		Networks: []Network{NetworkTCP},
		Limits:   Limits{MaxUnauthenticatedConnections: 1, MaxUnauthenticatedPerSource: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	obs := &recordingObserver{}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}, Observer: obs})
	if err != nil {
		t.Fatal(err)
	}
	src := &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 1000}

	block := make(chan struct{})
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	done := make(chan error, 1)
	go func() {
		done <- handler.ServeTCP(context.Background(), serverConn, src, func(ctx context.Context, raw net.Conn) (net.Conn, error) {
			<-block
			return raw, nil
		}, nil)
	}()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if handler.admission.active() == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if handler.admission.active() != 1 {
		t.Fatal("first connection did not take admission slot")
	}

	extraServer, extraClient := net.Pipe()
	err = handler.ServeTCP(context.Background(), extraServer, src, func(context.Context, net.Conn) (net.Conn, error) {
		t.Fatal("handshake should not run when admission is full")
		return nil, nil
	}, nil)
	_ = extraClient.Close()
	if !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("err=%v want ErrAdmissionLimit", err)
	}
	if !IsReported(err) {
		t.Fatal("admission rejection should be reported")
	}
	if !obs.hasCode("admission_limited") {
		t.Fatal("missing admission_limited event")
	}

	close(block)
	_ = clientConn.Close()
	<-done
}

func TestServeTCPReleasesAdmissionAfterAuthSuccess(t *testing.T) {
	config, err := NewConfig(ConfigOptions{
		Password: "secret",
		Networks: []Network{NetworkTCP},
		Limits:   Limits{MaxUnauthenticatedConnections: 1, MaxUnauthenticatedPerSource: 1},
		Timeouts: Timeouts{Auth: 50 * time.Millisecond, RequestIdle: 50 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	routed := make(chan struct{}, 1)
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: upstreamFuncs{
		stream: func(context.Context, net.Conn, net.Addr, string) error {
			select {
			case routed <- struct{}{}:
			default:
			}
			return nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	src := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 22}

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	done := make(chan error, 1)
	go func() {
		done <- handler.ServeTCP(context.Background(), serverConn, src, func(_ context.Context, raw net.Conn) (net.Conn, error) {
			return raw, nil
		}, nil)
	}()

	auth, _, err := wire.MakeAuthFrame("secret", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(auth); err != nil {
		t.Fatal(err)
	}
	req, err := wire.EncodeTCPRequest("example.com:443", config.EffectiveSpec())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(req); err != nil {
		t.Fatal(err)
	}

	select {
	case <-routed:
	case <-time.After(time.Second):
		t.Fatal("upstream was not invoked")
	}
	if handler.admission.active() != 0 {
		t.Fatalf("admission not released after auth success: active=%d", handler.admission.active())
	}
	_ = clientConn.Close()
	<-done
}

func TestServeTCPClassifiesTLSHandshakeLevels(t *testing.T) {
	config, err := NewConfig(ConfigOptions{Password: "secret", Networks: []Network{NetworkTCP}})
	if err != nil {
		t.Fatal(err)
	}
	obs := &recordingObserver{}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}, Observer: obs})
	if err != nil {
		t.Fatal(err)
	}
	src := &net.TCPAddr{IP: net.ParseIP("192.0.2.8"), Port: 9}

	serverConn, clientConn := net.Pipe()
	_ = clientConn.Close()
	err = handler.ServeTCP(context.Background(), serverConn, src, func(_ context.Context, _ net.Conn) (net.Conn, error) {
		return nil, io.EOF
	}, nil)
	if !IsReported(err) {
		t.Fatal("tls failure should be reported")
	}
	if level, ok := obs.levelFor("tls_handshake_failed"); !ok || level != diagnostic.LevelDebug {
		t.Fatalf("EOF handshake level=%v ok=%v want DEBUG", level, ok)
	}

	obs2 := &recordingObserver{}
	handler.observer = obs2
	serverConn2, clientConn2 := net.Pipe()
	_ = clientConn2.Close()
	_ = handler.ServeTCP(context.Background(), serverConn2, src, func(_ context.Context, _ net.Conn) (net.Conn, error) {
		return nil, context.DeadlineExceeded
	}, nil)
	if level, ok := obs2.levelFor("tls_handshake_failed"); !ok || level != diagnostic.LevelWarn {
		t.Fatalf("deadline handshake level=%v ok=%v want WARN", level, ok)
	}
}

func TestClassifyTLSHandshake(t *testing.T) {
	if got := classifyTLSHandshake(io.EOF); got != diagnostic.LevelDebug {
		t.Fatalf("EOF -> %v", got)
	}
	if got := classifyTLSHandshake(context.DeadlineExceeded); got != diagnostic.LevelWarn {
		t.Fatalf("deadline -> %v", got)
	}
	if got := classifyTLSHandshake(errors.New("tls: bad certificate")); got != diagnostic.LevelError {
		t.Fatalf("other -> %v", got)
	}
}

type recordingObserver struct {
	mu     sync.Mutex
	events []diagnostic.Event
}

func (o *recordingObserver) Observe(_ context.Context, event diagnostic.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, event)
}

func (o *recordingObserver) hasCode(code string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, event := range o.events {
		if event.Code == code {
			return true
		}
	}
	return false
}

func (o *recordingObserver) levelFor(code string) (diagnostic.Level, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, event := range o.events {
		if event.Code == code {
			return event.Level, true
		}
	}
	return 0, false
}
