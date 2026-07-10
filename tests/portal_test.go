package tests_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/bundle"
	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

// In-memory fake portal: auth + TCP request + echo (no network).
func TestPortalSymmetricTCPEcho(t *testing.T) {
	spec, err := wire.BuildEffectiveSpec("secret", "auto", "now/1")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var portalErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		portalErr = serveFakePortalOnce(ln, "secret", spec, []byte("pong"))
	}()

	cfg, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address: ln.Addr().String(), Spec: spec, Key: "secret",
		Dialer: &netDialer{}, TLSDialer: &plainTLS{},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.NewCarrierBundle(bundle.BundleOptions{
		TCP:      cfg,
		PoolSize: 0,
		Up:       wire.CarrierTCP,
		Down:     wire.CarrierTCP,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := b.SymmetricOpenTCP(ctx, "example.com:443")
	if err != nil {
		t.Fatalf("SymmetricOpenTCP: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "pong" {
		t.Fatalf("echo = %q, want pong", got)
	}

	_ = ln.Close()
	wg.Wait()
	if portalErr != nil && !errors.Is(portalErr, net.ErrClosed) {
		t.Fatalf("portal: %v", portalErr)
	}
}

func serveFakePortalOnce(ln net.Listener, key string, spec *wire.EffectiveSpec, reply []byte) error {
	c, err := ln.Accept()
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := wire.ReadAuthFrame(c, key, spec); err != nil {
		return err
	}
	target, err := wire.DecodeTCPRequest(c, spec)
	if err != nil {
		return err
	}
	if target != "example.com:443" {
		return err
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if !bytes.Equal(buf[:n], []byte("ping")) {
		return errors.New("unexpected client payload")
	}
	_, err = c.Write(reply)
	return err
}

type netDialer struct{}

func (netDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// plainTLS skips TLS for in-process tests.
type plainTLS struct{}

func (plainTLS) DialTLSConn(_ context.Context, c net.Conn) (net.Conn, error) { return c, nil }

var _ carrier.Logger = carrier.NopLogger{}
