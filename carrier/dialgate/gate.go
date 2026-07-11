// Package dialgate provides portal dial single-flight coalesce and jittered backoff.
package dialgate

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultInitial is the first retry delay after connection refused / dial timeout.
	DefaultInitial = 200 * time.Millisecond
	// DefaultMax caps exponential dial backoff.
	DefaultMax = 5 * time.Second
	// DefaultAuthBackoff is applied after authentication / protocol failures.
	DefaultAuthBackoff = 30 * time.Second
)

// Classifies dial/establish failures for backoff policy.
type Class int

const (
	ClassOK Class = iota
	ClassRetryable
	ClassAuth
	ClassOther
	ClassCanceled
)

// Classify maps an establish error to a backoff class.
func Classify(err error) Class {
	if err == nil {
		return ClassOK
	}
	if errors.Is(err, context.Canceled) {
		return ClassCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ClassRetryable
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "authentication"),
		strings.Contains(msg, "auth failed"),
		strings.Contains(msg, "invalid password"),
		strings.Contains(msg, "wrong password"),
		strings.Contains(msg, "spec mismatch"),
		strings.Contains(msg, "unknown version"),
		strings.Contains(msg, "bad auth"):
		return ClassAuth
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "timeout"),
		strings.Contains(msg, "temporarily unavailable"),
		strings.Contains(msg, "connect: "):
		return ClassRetryable
	default:
		return ClassOther
	}
}

// Options configures a Gate.
type Options struct {
	Initial     time.Duration
	Max         time.Duration
	AuthBackoff time.Duration
	// AlwaysCoalesce forces single-flight even while healthy (QUIC session).
	AlwaysCoalesce bool
}

// Gate coalesces concurrent portal establish attempts while degraded and
// applies jittered backoff. Healthy (post-success) dials run in parallel.
type Gate struct {
	initial        time.Duration
	max            time.Duration
	authBackoff    time.Duration
	alwaysCoalesce bool

	mu          sync.Mutex
	nextAllowed time.Time
	step        int
	flight      *flight
	failErr     error
	degraded    bool

	attempts atomic.Uint64
}

type flight struct {
	done chan struct{}
	err  error
}

// New builds a Gate with defaults for zero durations.
func New(opts Options) *Gate {
	initial := opts.Initial
	if initial <= 0 {
		initial = DefaultInitial
	}
	max := opts.Max
	if max <= 0 {
		max = DefaultMax
	}
	if initial > max {
		initial = max
	}
	auth := opts.AuthBackoff
	if auth <= 0 {
		auth = DefaultAuthBackoff
	}
	return &Gate{initial: initial, max: max, authBackoff: auth, alwaysCoalesce: opts.AlwaysCoalesce}
}

// Attempts returns how many times the dial function ran.
func (g *Gate) Attempts() uint64 {
	if g == nil {
		return 0
	}
	return g.attempts.Load()
}

// Run executes fn. While the gate is healthy, callers dial in parallel.
// After a retryable/auth failure the gate becomes degraded: concurrent callers
// share one probe (or the last error inside the backoff window) so a down
// portal cannot be hammered. Success clears degraded and restores parallelism.
func (g *Gate) Run(ctx context.Context, fn func(context.Context) error) error {
	if g == nil {
		return fn(ctx)
	}
	for {
		g.mu.Lock()
		degraded := g.degraded || g.alwaysCoalesce
		if !degraded {
			g.mu.Unlock()
			g.attempts.Add(1)
			err := fn(ctx)
			g.note(err)
			return err
		}

		if f := g.flight; f != nil {
			g.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-f.done:
				if f.err != nil {
					return f.err
				}
				// Probe succeeded: mint our own carrier outside the flight.
				g.attempts.Add(1)
				err := fn(ctx)
				g.note(err)
				return err
			}
		}
		now := time.Now()
		if g.failErr != nil && now.Before(g.nextAllowed) {
			err := g.failErr
			g.mu.Unlock()
			return err
		}
		if delay := time.Until(g.nextAllowed); delay > 0 {
			g.mu.Unlock()
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}

		f := &flight{done: make(chan struct{})}
		g.flight = f
		g.mu.Unlock()

		g.attempts.Add(1)
		err := fn(ctx)
		g.note(err)

		g.mu.Lock()
		f.err = err
		g.flight = nil
		close(f.done)
		g.mu.Unlock()
		return err
	}
}

func (g *Gate) note(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch Classify(err) {
	case ClassOK:
		g.step = 0
		g.nextAllowed = time.Time{}
		g.failErr = nil
		g.degraded = false
	case ClassCanceled:
		// Do not advance backoff on local cancel.
	case ClassAuth, ClassOther:
		g.degraded = true
		g.failErr = err
		g.step = 0
		g.nextAllowed = time.Now().Add(g.authBackoff)
	case ClassRetryable:
		g.degraded = true
		g.failErr = err
		delay := g.initial << g.step
		if delay > g.max || delay <= 0 {
			delay = g.max
		}
		if g.step < 16 {
			g.step++
		}
		jittered := delay/2 + time.Duration(rand.Int63n(int64(delay/2)+1))
		g.nextAllowed = time.Now().Add(jittered)
	}
}
