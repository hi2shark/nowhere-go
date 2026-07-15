package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

const setupResultWriteTimeout = time.Second

// FlowReadiness is resolved by Upstream only after the real target is ready or rejected.
type FlowReadiness interface {
	Ready() error
	Reject(cause error) error
}

type flowReadiness struct {
	once          sync.Once
	mu            sync.Mutex
	ready         func() error
	reject        func(wire.FlowErrorCode) error
	onReady       func()
	resolved      bool
	readyResolved bool
	done          chan struct{}
	err           error
}

func newFlowReadiness(ready func() error, reject func(wire.FlowErrorCode) error) *flowReadiness {
	return &flowReadiness{ready: ready, reject: reject, done: make(chan struct{})}
}

func (r *flowReadiness) Ready() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		if r.ready != nil {
			r.err = r.ready()
		}
		r.mu.Lock()
		r.resolved = true
		r.readyResolved = r.err == nil
		onReady := r.onReady
		r.mu.Unlock()
		if r.err == nil && onReady != nil {
			onReady()
		}
		close(r.done)
	})
	<-r.done
	return r.err
}

func (r *flowReadiness) Reject(cause error) error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		if r.reject != nil {
			r.err = r.reject(setupFailureCode(cause))
		}
		r.mu.Lock()
		r.resolved = true
		r.mu.Unlock()
		close(r.done)
	})
	<-r.done
	return r.err
}

func (r *flowReadiness) setOnReady(callback func()) {
	if r == nil || callback == nil {
		return
	}
	r.mu.Lock()
	if r.readyResolved {
		r.mu.Unlock()
		callback()
		return
	}
	if r.resolved {
		r.mu.Unlock()
		return
	}
	previous := r.onReady
	r.onReady = func() {
		if previous != nil {
			previous()
		}
		callback()
	}
	r.mu.Unlock()
}

func (r *flowReadiness) Wait(ctx context.Context) error {
	if r == nil {
		return nil
	}
	select {
	case <-r.done:
		return r.err
	case <-ctx.Done():
		cause := context.Cause(ctx)
		if cause == nil {
			cause = ctx.Err()
		}
		return r.Reject(cause)
	}
}

type setupResultFormat uint8

const (
	setupResultF2 setupResultFormat = iota
	setupResultUOT
)

type setupResult struct {
	mu        sync.Mutex
	writer    net.Conn
	format    setupResultFormat
	committed bool
}

func newSetupResult(writer net.Conn, kind wire.FlowKind, downlink wire.Carrier) *setupResult {
	format := setupResultF2
	if kind == wire.FlowKindUDP && downlink == wire.CarrierTCP {
		format = setupResultUOT
	}
	return &setupResult{writer: writer, format: format}
}

func (r *setupResult) ready() error {
	return r.commit(wire.FlowResult{Status: wire.FlowStatusReady})
}

func (r *setupResult) reject(code wire.FlowErrorCode) error {
	return r.commit(wire.FlowResult{Status: wire.FlowStatusReject, Code: code})
}

func (r *setupResult) rejectContext(ctx context.Context, code wire.FlowErrorCode) error {
	return r.commitContext(ctx, wire.FlowResult{Status: wire.FlowStatusReject, Code: code})
}

func (r *setupResult) commit(result wire.FlowResult) error {
	return r.commitContext(context.Background(), result)
}

func (r *setupResult) commitContext(ctx context.Context, result wire.FlowResult) error {
	if r == nil || r.writer == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.committed {
		return nil
	}
	r.committed = true
	deadline := time.Now().Add(setupResultWriteTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	_ = r.writer.SetWriteDeadline(deadline)
	defer r.writer.SetWriteDeadline(time.Time{})
	if ctx.Err() != nil {
		_ = r.writer.Close()
	} else if ctx.Done() != nil {
		stop := afterContextFunc(ctx, func() { _ = r.writer.Close() })
		defer stop()
	}
	if r.format == setupResultUOT {
		frame := wire.UOTFrame{Kind: wire.UOTFrameReady}
		if result.Status == wire.FlowStatusReject {
			frame = wire.UOTFrame{Kind: wire.UOTFrameReject, Code: result.Code}
		}
		return wire.WriteUOTFrame(r.writer, frame)
	}
	frame, err := wire.WriteFlowResult(result)
	if err != nil {
		return err
	}
	return writeAll(r.writer, frame[:])
}

func setupFailureCode(err error) wire.FlowErrorCode {
	var flowErr *wire.FlowError
	if errors.As(err, &flowErr) && flowErr.Code != 0 {
		return flowErr.Code
	}
	switch {
	case errors.Is(err, ErrCarrierMismatch), errors.Is(err, ErrDuplicateHalf):
		return wire.FlowErrorCodeMetadataConflict
	case errors.Is(err, ErrPairTimeout):
		return wire.FlowErrorCodePairTimeout
	case errors.Is(err, ErrPairLimit), errors.Is(err, ErrSessionLimit):
		return wire.FlowErrorCodeFlowLimit
	case errors.Is(err, ErrClosed), errors.Is(err, net.ErrClosed), errors.Is(err, context.Canceled):
		return wire.FlowErrorCodeSessionReplaced
	case errors.Is(err, ErrInvalidHandler), errors.Is(err, ErrUpstreamNotConfigured):
		return wire.FlowErrorCodeInternalError
	default:
		return wire.FlowErrorCodeDialFailed
	}
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}
