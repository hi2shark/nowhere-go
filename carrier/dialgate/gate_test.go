package dialgate

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClassifyRetryableAndAuth(t *testing.T) {
	if Classify(errors.New("dial tcp: connection refused")) != ClassRetryable {
		t.Fatal("want retryable")
	}
	if Classify(errors.New("authentication failed")) != ClassAuth {
		t.Fatal("want auth")
	}
	if Classify(context.Canceled) != ClassCanceled {
		t.Fatal("want canceled")
	}
}

func TestGateCoalescesConcurrentRefused(t *testing.T) {
	gate := New(Options{Initial: 500 * time.Millisecond, Max: time.Second})
	refused := errors.New("connect: connection refused")

	// Seed degraded state with one failure.
	if err := gate.Run(context.Background(), func(context.Context) error { return refused }); err == nil {
		t.Fatal("expected refused")
	}
	seedAttempts := gate.Attempts()

	var dials atomic.Uint64
	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := gate.Run(context.Background(), func(context.Context) error {
				dials.Add(1)
				return refused
			})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil {
			t.Fatal("expected error")
		}
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("dials during backoff coalesce=%d, want 0", got)
	}
	if gate.Attempts() != seedAttempts {
		t.Fatalf("attempts=%d, want seed %d", gate.Attempts(), seedAttempts)
	}
}

func TestGateAuthDoesNotTightLoop(t *testing.T) {
	gate := New(Options{
		Initial:     10 * time.Millisecond,
		Max:         20 * time.Millisecond,
		AuthBackoff: 200 * time.Millisecond,
	})
	authErr := errors.New("authentication failed: bad password")
	if err := gate.Run(context.Background(), func(context.Context) error { return authErr }); err == nil {
		t.Fatal("expected auth error")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	err := gate.Run(ctx, func(context.Context) error {
		t.Fatal("should not dial during auth backoff")
		return nil
	})
	if err == nil {
		t.Fatal("expected error during auth backoff")
	}
	if gate.Attempts() != 1 {
		t.Fatalf("attempts=%d, want 1", gate.Attempts())
	}
}

func TestGateSuccessClearsBackoff(t *testing.T) {
	gate := New(Options{Initial: 100 * time.Millisecond, Max: time.Second})
	_ = gate.Run(context.Background(), func(context.Context) error {
		return &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	})
	if err := gate.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
		// May still be in backoff coalesce returning refused — wait it out.
		time.Sleep(150 * time.Millisecond)
		if err := gate.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if err := gate.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatalf("success did not clear backoff")
	}
}

func TestGateHealthyParallel(t *testing.T) {
	gate := New(Options{})
	var active atomic.Int32
	var max atomic.Int32
	const n = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = gate.Run(context.Background(), func(context.Context) error {
				cur := active.Add(1)
				for {
					old := max.Load()
					if cur <= old || max.CompareAndSwap(old, cur) {
						break
					}
				}
				time.Sleep(30 * time.Millisecond)
				active.Add(-1)
				return nil
			})
		}()
	}
	close(start)
	wg.Wait()
	if max.Load() < int32(n) {
		t.Fatalf("max parallel=%d, want %d", max.Load(), n)
	}
}
