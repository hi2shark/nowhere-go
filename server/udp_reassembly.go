package server

import (
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

// byteBudget is shared by queued UDP packets and retained reassembly output.
// It deliberately has no protocol knowledge; the wire package owns fragment
// validation and reassembly.
type byteBudget struct {
	mu    sync.Mutex
	limit int
	used  int
}

func (b *byteBudget) reserve(count int) bool {
	if b == nil || count < 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit > 0 && b.used+count > b.limit {
		return false
	}
	b.used += count
	return true
}

func (b *byteBudget) release(count int) {
	if b == nil || count <= 0 {
		return
	}
	b.mu.Lock()
	b.used -= count
	if b.used < 0 {
		b.used = 0
	}
	b.mu.Unlock()
}

// udpReassembler is a server-lifetime wrapper around wire.DatagramReassembler.
// Keeping queue accounting here lets a completed packet retain its budget until
// the receiving flow consumes it, while all fragment parsing remains in wire.
type udpReassembler struct {
	mu       sync.Mutex
	inner    *wire.DatagramReassembler
	budget   *byteBudget
	closed   bool
}

type reassemblyOutcome struct {
	Packet   []byte
	Complete bool
	Dropped  bool
	Release  func()
}

func newUDPReassembler(maxSlots int, ttl time.Duration, budget *byteBudget) *udpReassembler {
	if budget == nil {
		budget = &byteBudget{}
	}
	cfg := wire.DefaultReassemblyConfig()
	if maxSlots > 0 {
		cfg.MaxSlots = maxSlots
	}
	if ttl > 0 {
		cfg.TTL = ttl
	}
	if budget.limit > 0 && budget.limit < cfg.MaxBytes {
		cfg.MaxBytes = budget.limit
	}
	return &udpReassembler{inner: wire.NewDatagramReassembler(cfg), budget: budget}
}

func (r *udpReassembler) Push(flowID wire.FlowID, fragment wire.UDPFragment, now time.Time) reassemblyOutcome {
	if r == nil || flowID == 0 {
		return reassemblyOutcome{Dropped: true}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.inner == nil {
		return reassemblyOutcome{Dropped: true}
	}
	outcome := r.inner.Push(flowID, fragment, now)
	if outcome.DropReason != wire.ReassemblyDropNone || !outcome.Done {
		return reassemblyOutcome{Dropped: outcome.DropReason != wire.ReassemblyDropNone}
	}
	payload := outcome.Payload
	if !r.budget.reserve(len(payload)) {
		return reassemblyOutcome{Dropped: true}
	}
	var once sync.Once
	return reassemblyOutcome{
		Packet: payload, Complete: true,
		Release: func() { once.Do(func() { r.budget.release(len(payload)) }) },
	}
}

func (r *udpReassembler) Expire(now time.Time) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed && r.inner != nil {
		r.inner.Expire(now)
	}
}

func (r *udpReassembler) RemoveFlow(flowID wire.FlowID) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed && r.inner != nil {
		r.inner.RemoveFlow(flowID)
	}
}

func (r *udpReassembler) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	if r.inner != nil {
		r.inner.Clear()
	}
}
