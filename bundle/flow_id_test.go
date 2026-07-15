package bundle

import (
	"context"
	"errors"
	"math"
	"net"
	"sync"
	"testing"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestFlowIDAllocatorMonotonicNonZero(t *testing.T) {
	bundle := &CarrierBundle{}
	bundle.nextFlowID.Store(1)
	for want := uint64(1); want <= 128; want++ {
		got, err := bundle.allocFlowID()
		if err != nil {
			t.Fatalf("allocFlowID(%d): %v", want, err)
		}
		if got != want {
			t.Fatalf("allocFlowID(%d) = %d, want %d", want, got, want)
		}
	}
}

func TestFlowIDAllocatorConcurrentUnique(t *testing.T) {
	const (
		workers = 32
		perWork = 128
	)
	bundle := &CarrierBundle{}
	bundle.nextFlowID.Store(1)

	type result struct {
		id  uint64
		err error
	}
	results := make(chan result, workers*perWork)
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for attempt := 0; attempt < perWork; attempt++ {
				id, err := bundle.allocFlowID()
				results <- result{id: id, err: err}
			}
		}()
	}
	group.Wait()
	close(results)

	seen := make(map[uint64]struct{}, workers*perWork)
	for result := range results {
		if result.err != nil {
			t.Fatalf("allocFlowID: %v", result.err)
		}
		if result.id == 0 {
			t.Fatal("allocFlowID returned zero")
		}
		if _, exists := seen[result.id]; exists {
			t.Fatalf("duplicate flow id %d", result.id)
		}
		seen[result.id] = struct{}{}
	}
	if len(seen) != workers*perWork {
		t.Fatalf("unique flow ids = %d, want %d", len(seen), workers*perWork)
	}
}

func TestFlowIDAllocatorExhaustionDoesNotWrap(t *testing.T) {
	bundle := &CarrierBundle{}
	bundle.nextFlowID.Store(math.MaxUint64 - 1)

	for _, want := range []uint64{math.MaxUint64 - 1, math.MaxUint64} {
		got, err := bundle.allocFlowID()
		if err != nil || got != want {
			t.Fatalf("allocFlowID = (%d, %v), want (%d, nil)", got, err, want)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		got, err := bundle.allocFlowID()
		if got != 0 || !errors.Is(err, ErrFlowIDExhausted) {
			t.Fatalf("allocFlowID after exhaustion = (%d, %v), want (0, %v)", got, err, ErrFlowIDExhausted)
		}
	}
}

func TestFlowIDExhaustionPropagatesFromEveryOpenPath(t *testing.T) {
	tcpConfig, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address:   "127.0.0.1:1",
		Spec:      mustNowhereSpec(t),
		Key:       "k",
		Dialer:    flowIDFailDialer{},
		TLSDialer: passthroughTLSDialer{},
	})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	for _, test := range []struct {
		name string
		up   wire.Carrier
		down wire.Carrier
		open func(*CarrierBundle) error
	}{
		{name: "symmetric-tcp-open-tcp", up: wire.CarrierTCP, down: wire.CarrierTCP, open: func(bundle *CarrierBundle) error {
			_, err := bundle.OpenTCP(context.Background(), "example.com:443")
			return err
		}},
		{name: "symmetric-quic-open-tcp", up: wire.CarrierUDP, down: wire.CarrierUDP, open: func(bundle *CarrierBundle) error {
			_, err := bundle.OpenTCP(context.Background(), "example.com:443")
			return err
		}},
		{name: "asymmetric-open-tcp", up: wire.CarrierTCP, down: wire.CarrierUDP, open: func(bundle *CarrierBundle) error {
			_, err := bundle.OpenTCP(context.Background(), "example.com:443")
			return err
		}},
		{name: "symmetric-tcp-open-udp", up: wire.CarrierTCP, down: wire.CarrierTCP, open: func(bundle *CarrierBundle) error {
			_, err := bundle.OpenUDP(context.Background(), "example.com:53")
			return err
		}},
		{name: "symmetric-quic-open-udp", up: wire.CarrierUDP, down: wire.CarrierUDP, open: func(bundle *CarrierBundle) error {
			_, err := bundle.OpenUDP(context.Background(), "example.com:53")
			return err
		}},
		{name: "asymmetric-open-udp", up: wire.CarrierUDP, down: wire.CarrierTCP, open: func(bundle *CarrierBundle) error {
			_, err := bundle.OpenUDP(context.Background(), "example.com:53")
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := BundleOptions{TCP: tcpConfig, Up: test.up, Down: test.down}
			if test.up == wire.CarrierUDP || test.down == wire.CarrierUDP {
				options.QUIC = flowIDFailBackend{}
			}
			bundle, err := NewCarrierBundle(options)
			if err != nil {
				t.Fatalf("NewCarrierBundle: %v", err)
			}
			bundle.nextFlowID.Store(0)
			if err := test.open(bundle); !errors.Is(err, ErrFlowIDExhausted) {
				t.Fatalf("open error = %v, want %v", err, ErrFlowIDExhausted)
			}
		})
	}
}

type flowIDFailDialer struct{}

func (flowIDFailDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("test: carrier reached after flow id exhaustion")
}

type flowIDFailBackend struct{}

func (flowIDFailBackend) SetSessionID(wire.SessionID) {}
func (flowIDFailBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return nil, errors.New("test: carrier reached after flow id exhaustion")
}
func (flowIDFailBackend) InvalidateSession(carrier.QuicSession) {}
func (flowIDFailBackend) Close() error                          { return nil }

var _ quic.Backend = flowIDFailBackend{}
