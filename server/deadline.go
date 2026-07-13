package server

import (
	"os"
	"sync"
	"time"
)

type deadlineState struct {
	mu      sync.Mutex
	value   time.Time
	changed chan struct{}
}

type deadlineReadWait struct {
	state   *deadlineState
	changed <-chan struct{}
	timer   *time.Timer
	timerC  <-chan time.Time
}

func (d *deadlineState) set(value time.Time) {
	d.mu.Lock()
	if d.changed == nil {
		d.changed = make(chan struct{})
	}
	previous := d.changed
	d.value = value
	d.changed = make(chan struct{})
	close(previous)
	d.mu.Unlock()
}

func (d *deadlineState) snapshot() (time.Time, <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.changed == nil {
		d.changed = make(chan struct{})
	}
	return d.value, d.changed
}

func (d *deadlineState) expired(now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return deadlineExpired(d.value, now)
}

func (d *deadlineState) newReadWait(now time.Time) (deadlineReadWait, bool) {
	value, changed := d.snapshot()
	wait := deadlineReadWait{state: d, changed: changed}
	if deadlineExpired(value, now) {
		return wait, true
	}
	if !value.IsZero() {
		wait.timer = time.NewTimer(value.Sub(now))
		wait.timerC = wait.timer.C
	}
	return wait, false
}

func (d *deadlineState) generationExpired(generation <-chan struct{}, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.changed == generation && deadlineExpired(d.value, now)
}

func (w deadlineReadWait) stop() {
	if w.timer == nil {
		return
	}
	// The read goroutine is the timer's only receiver, and stop is called only
	// after select chose a non-timer case, so a failed Go 1.20 Stop must be drained.
	if !w.timer.Stop() {
		<-w.timer.C
	}
}

func (w deadlineReadWait) timerExpired(now time.Time) bool {
	return w.state.generationExpired(w.changed, now)
}

func deadlineExpired(value, now time.Time) bool {
	return !value.IsZero() && !now.Before(value)
}

func deadlineError() error { return os.ErrDeadlineExceeded }
