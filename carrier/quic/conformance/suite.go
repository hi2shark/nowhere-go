// Package conformance provides host-neutral checks for QUIC adapters.
package conformance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

const operationTimeout = time.Second

// Harness describes one disposable, instrumented QUIC adapter. Send, Receive,
// and optional Accept must block until their context ends or Shutdown closes
// the physical session.
type Harness struct {
	ExpectedALPN string

	TLSHandshakeInfo func() (wire.TLSHandshakeInfo, error)
	Send             func(context.Context) error
	Receive          func(context.Context) error
	Accept           func(context.Context) error
	Shutdown         func() error

	MarkAuthenticated func()
	Authenticated     func() bool
}

// Check exercises the common outbound Session and inbound QuicConn contracts.
func Check(h Harness) error {
	if h.TLSHandshakeInfo == nil || h.Send == nil || h.Receive == nil || h.Shutdown == nil {
		return errors.New("nowhere: incomplete QUIC conformance harness")
	}
	info, err := h.TLSHandshakeInfo()
	if err != nil {
		return fmt.Errorf("handshake info: %w", err)
	}
	if err := info.Validate(h.ExpectedALPN); err != nil {
		return fmt.Errorf("handshake validation: %w", err)
	}

	if err := checkCanceled("SendDatagram", h.Send); err != nil {
		return err
	}
	if err := checkDeadline("SendDatagram", h.Send); err != nil {
		return err
	}
	if err := checkDeadline("ReceiveDatagram", h.Receive); err != nil {
		return err
	}

	if h.MarkAuthenticated != nil || h.Authenticated != nil {
		if h.MarkAuthenticated == nil || h.Authenticated == nil {
			return errors.New("nowhere: incomplete authentication notification harness")
		}
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				h.MarkAuthenticated()
			}()
		}
		wg.Wait()
		if !h.Authenticated() {
			return errors.New("nowhere: authentication notification was not retained")
		}
	}

	operations := []struct {
		name string
		run  func(context.Context) error
	}{
		{name: "SendDatagram", run: h.Send},
		{name: "ReceiveDatagram", run: h.Receive},
	}
	if h.Accept != nil {
		operations = append(operations, struct {
			name string
			run  func(context.Context) error
		}{name: "AcceptStream", run: h.Accept})
	}
	results := make(chan operationResult, len(operations))
	for _, operation := range operations {
		operation := operation
		go func() {
			results <- operationResult{name: operation.name, err: operation.run(context.Background())}
		}()
	}

	shutdownResults := make(chan error, 16)
	for i := 0; i < cap(shutdownResults); i++ {
		go func() { shutdownResults <- h.Shutdown() }()
	}
	deadline := time.NewTimer(operationTimeout)
	defer deadline.Stop()
	for range operations {
		select {
		case result := <-results:
			if result.err == nil {
				return fmt.Errorf("%s returned nil after shutdown", result.name)
			}
		case <-deadline.C:
			return errors.New("nowhere: QUIC shutdown did not unblock all operations")
		}
	}
	for i := 0; i < cap(shutdownResults); i++ {
		select {
		case err := <-shutdownResults:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("concurrent shutdown: %w", err)
			}
		case <-deadline.C:
			return errors.New("nowhere: concurrent QUIC shutdown deadlocked")
		}
	}
	return nil
}

type operationResult struct {
	name string
	err  error
}

func checkCanceled(name string, operation func(context.Context) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := operation(ctx); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s canceled error = %v, want context.Canceled", name, err)
	}
	return nil
}

func checkDeadline(name string, operation func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := operation(ctx); !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s deadline error = %v, want context.DeadlineExceeded", name, err)
	}
	return nil
}
