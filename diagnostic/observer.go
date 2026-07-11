// Package diagnostic defines structured, host-owned observability hooks.
package diagnostic

import (
	"context"
	"net"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

// Level is the severity of an Event.
type Level uint8

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// Event is a structured diagnostic emitted by the protocol core.
// Zero-valued fields are omitted by host adapters.
type Event struct {
	Level     Level
	Code      string
	Component string
	Source    net.Addr
	Target    string
	SessionID wire.SessionID
	FlowID    uint64
	CarrierID uint64
	State     string
	Outcome   string
	Count     int
	Bytes     uint64
	Duration  time.Duration
	Err       error

	// Half / pair correlation fields (asymmetric flows).
	HalfRole      string // "open" | "attach"
	Transport     string // "tcp" | "quic" | "udp"
	Stage         string // prepare | commit | pair_wait | ...
	MissingHalf   string // complementary role when waiting/timeout
	ContextCause  string // context cancel cause / timeout reason
	DialQueueMs   int64
	RawDialMs     int64
	TLSms         int64
	AuthMs        int64
	PairWaitMs    int64
}

// Observer receives diagnostic events. Implementations must return promptly.
type Observer interface {
	Observe(context.Context, Event)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(context.Context, Event)

func (f ObserverFunc) Observe(ctx context.Context, event Event) { f(ctx, event) }

// NopObserver discards events.
type NopObserver struct{}

func (NopObserver) Observe(context.Context, Event) {}

// Emit invokes observer while isolating host observer panics from protocol goroutines.
func Emit(ctx context.Context, observer Observer, event Event) {
	if observer == nil {
		return
	}
	defer func() { _ = recover() }()
	observer.Observe(ctx, event)
}
