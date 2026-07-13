package server

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

const (
	deadlineReadSettle  = 20 * time.Millisecond
	deadlineReadNear    = 80 * time.Millisecond
	deadlineReadFar     = 300 * time.Millisecond
	deadlineReadTimeout = time.Second
)

type readDeadlineEndpoint struct {
	read            func() ([]byte, error)
	setReadDeadline func(time.Time) error
	deliver         func([]byte) error
	close           func() error
}

type readDeadlineResult struct {
	payload []byte
	err     error
}

type readDeadlineFactory func(*testing.T) *readDeadlineEndpoint

func TestDeadlineReadWaitValidatesGenerationBeforeTimeout(t *testing.T) {
	t.Run("current generation requires expired deadline", func(t *testing.T) {
		var state deadlineState
		deadline := time.Now().Add(20 * time.Millisecond)
		state.set(deadline)
		wait, expired := state.newReadWait(time.Now())
		if expired {
			t.Fatal("fresh deadline was already expired")
		}
		if wait.timerExpired(deadline.Add(-time.Nanosecond)) {
			t.Fatal("current generation timed out before its deadline")
		}
		select {
		case <-wait.timerC:
		case <-time.After(deadlineReadTimeout):
			t.Fatal("current generation timer did not fire")
		}
		if !wait.timerExpired(time.Now()) {
			t.Fatal("current generation did not time out after its deadline")
		}
	})

	for _, test := range []struct {
		name  string
		value func() time.Time
	}{
		{name: "extended generation", value: func() time.Time { return time.Now().Add(time.Hour) }},
		{name: "cleared generation", value: func() time.Time { return time.Time{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var state deadlineState
			oldDeadline := time.Now().Add(20 * time.Millisecond)
			state.set(oldDeadline)
			wait, expired := state.newReadWait(time.Now())
			if expired {
				t.Fatal("fresh old deadline was already expired")
			}

			state.set(test.value())
			select {
			case <-wait.changed:
			case <-time.After(deadlineReadTimeout):
				t.Fatal("old generation was not closed by deadline update")
			}
			select {
			case <-wait.timerC:
			case <-time.After(deadlineReadTimeout):
				t.Fatal("old generation timer did not fire")
			}
			if wait.timerExpired(time.Now()) {
				t.Fatal("stale timer expired the updated deadline generation")
			}
		})
	}
}

func TestCompactUDPReadDeadlineContract(t *testing.T) {
	runReadDeadlineContract(t, func(t *testing.T) *readDeadlineEndpoint {
		t.Helper()
		session := newCompactTestSession(t, Limits{}, nil, nil)
		flow := newCompactUDPFlow(session, 301, "deadline-compact.example:53", wire.CarrierUDP)
		return &readDeadlineEndpoint{
			read: func() ([]byte, error) {
				buffer := make([]byte, 64)
				n, _, err := flow.ReadFrom(buffer)
				return append([]byte(nil), buffer[:n]...), err
			},
			setReadDeadline: flow.SetReadDeadline,
			deliver: func(payload []byte) error {
				if !flow.deliver(payload) {
					return net.ErrClosed
				}
				return nil
			},
			close: flow.Close,
		}
	})
}

func TestLegacyUDPReadDeadlineContract(t *testing.T) {
	runReadDeadlineContract(t, func(t *testing.T) *readDeadlineEndpoint {
		t.Helper()
		session, _ := newUDPTestSession(t, Limits{}, nil)
		flow := newLegacyUDPFlow(session, legacyUDPKey{flowID: 302, target: "deadline-legacy.example:53"})
		return &readDeadlineEndpoint{
			read: func() ([]byte, error) {
				buffer := make([]byte, 64)
				n, _, err := flow.ReadFrom(buffer)
				return append([]byte(nil), buffer[:n]...), err
			},
			setReadDeadline: flow.SetReadDeadline,
			deliver: func(payload []byte) error {
				flow.deliver(payload)
				return nil
			},
			close: flow.Close,
		}
	})
}

func TestQUICUDPUplinkReadDeadlineContract(t *testing.T) {
	runReadDeadlineContract(t, func(t *testing.T) *readDeadlineEndpoint {
		t.Helper()
		uplink := newQUICUDPUplink(nil)
		return &readDeadlineEndpoint{
			read:            uplink.ReadPacket,
			setReadDeadline: uplink.SetReadDeadline,
			deliver: func(payload []byte) error {
				uplink.Deliver(payload)
				return nil
			},
			close: uplink.Close,
		}
	})
}

func TestPairedUDPConnReadDeadlinePropagatesToQUICUplink(t *testing.T) {
	runReadDeadlineContract(t, func(t *testing.T) *readDeadlineEndpoint {
		t.Helper()
		quicUplink := newQUICUDPUplink(nil)
		recordedUplink := &recordingReadDeadlineUplink{udpUplink: quicUplink}
		conn := newPairedUDPConn(&pairedUDP{
			FlowID:      303,
			Target:      "deadline-paired-quic.example:53",
			Uplink:      recordedUplink,
			Downlink:    newUDPPairTestDownlink(),
			IdleTimeout: time.Hour,
		})
		return &readDeadlineEndpoint{
			read: func() ([]byte, error) {
				buffer := make([]byte, 64)
				n, _, err := conn.ReadFrom(buffer)
				return append([]byte(nil), buffer[:n]...), err
			},
			setReadDeadline: func(value time.Time) error {
				if err := conn.SetReadDeadline(value); err != nil {
					return err
				}
				if !recordedUplink.observed(value) {
					return fmt.Errorf("paired QUIC deadline %v was not propagated", value)
				}
				return nil
			},
			deliver: func(payload []byte) error {
				quicUplink.Deliver(payload)
				return nil
			},
			close: conn.Close,
		}
	})
}

func TestPairedUDPConnReadDeadlinePropagatesToTCPUplink(t *testing.T) {
	runReadDeadlineContract(t, func(t *testing.T) *readDeadlineEndpoint {
		t.Helper()
		serverConn, clientConn := net.Pipe()
		trackedConn := &recordingReadDeadlineConn{Conn: serverConn}
		conn := newPairedUDPConn(&pairedUDP{
			FlowID:      304,
			Target:      "deadline-paired-tcp.example:53",
			Uplink:      newTCPUDPUplink(trackedConn),
			Downlink:    newUDPPairTestDownlink(),
			IdleTimeout: time.Hour,
		})
		return &readDeadlineEndpoint{
			read: func() ([]byte, error) {
				buffer := make([]byte, 64)
				n, _, err := conn.ReadFrom(buffer)
				return append([]byte(nil), buffer[:n]...), err
			},
			setReadDeadline: func(value time.Time) error {
				if err := conn.SetReadDeadline(value); err != nil {
					return err
				}
				if !trackedConn.observed(value) {
					return fmt.Errorf("paired TCP deadline %v was not propagated", value)
				}
				return nil
			},
			deliver: func(payload []byte) error {
				frame, err := wire.WriteUOTPacketFrame(payload)
				if err != nil {
					return err
				}
				_, err = clientConn.Write(frame)
				return err
			},
			close: func() error {
				err := conn.Close()
				_ = clientConn.Close()
				return err
			},
		}
	})
}

func runReadDeadlineContract(t *testing.T, factory readDeadlineFactory) {
	t.Helper()

	t.Run("set-after-block", func(t *testing.T) {
		endpoint := factory(t)
		defer endpoint.close()
		result := startDeadlineRead(t, endpoint)
		assertDeadlineReadPending(t, result, deadlineReadSettle)

		if err := endpoint.setReadDeadline(time.Now().Add(deadlineReadNear)); err != nil {
			t.Fatal(err)
		}
		assertDeadlineResult(t, endpoint, result, true)
	})

	t.Run("shorten-pending", func(t *testing.T) {
		endpoint := factory(t)
		defer endpoint.close()
		if err := endpoint.setReadDeadline(time.Now().Add(deadlineReadFar)); err != nil {
			t.Fatal(err)
		}
		result := startDeadlineRead(t, endpoint)
		assertDeadlineReadPending(t, result, deadlineReadSettle)

		if err := endpoint.setReadDeadline(time.Now().Add(deadlineReadNear)); err != nil {
			t.Fatal(err)
		}
		assertDeadlineResult(t, endpoint, result, true)
	})

	t.Run("extend-pending", func(t *testing.T) {
		endpoint := factory(t)
		defer endpoint.close()
		oldDeadline := time.Now().Add(deadlineReadNear)
		if err := endpoint.setReadDeadline(oldDeadline); err != nil {
			t.Fatal(err)
		}
		result := startDeadlineRead(t, endpoint)
		assertDeadlineReadPending(t, result, deadlineReadSettle)

		if err := endpoint.setReadDeadline(time.Now().Add(deadlineReadFar)); err != nil {
			t.Fatal(err)
		}
		assertDeadlineReadPending(t, result, time.Until(oldDeadline)+deadlineReadSettle)
		deliverAndAssertRead(t, endpoint, result)
	})

	t.Run("clear-pending", func(t *testing.T) {
		endpoint := factory(t)
		defer endpoint.close()
		oldDeadline := time.Now().Add(deadlineReadNear)
		if err := endpoint.setReadDeadline(oldDeadline); err != nil {
			t.Fatal(err)
		}
		result := startDeadlineRead(t, endpoint)
		assertDeadlineReadPending(t, result, deadlineReadSettle)

		if err := endpoint.setReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		assertDeadlineReadPending(t, result, time.Until(oldDeadline)+deadlineReadSettle)
		deliverAndAssertRead(t, endpoint, result)
	})

	t.Run("close-race", func(t *testing.T) {
		endpoint := factory(t)
		result := startDeadlineRead(t, endpoint)
		assertDeadlineReadPending(t, result, deadlineReadSettle)

		start := make(chan struct{})
		setDone := make(chan error, 1)
		closeDone := make(chan error, 1)
		go func() {
			<-start
			setDone <- endpoint.setReadDeadline(time.Now().Add(deadlineReadNear))
		}()
		go func() {
			<-start
			closeDone <- endpoint.close()
		}()
		close(start)
		_ = awaitDeadlineOperation(t, setDone, "SetReadDeadline")
		if err := awaitDeadlineOperation(t, closeDone, "Close"); err != nil {
			t.Fatalf("Close during deadline update = %v", err)
		}
		readResult := awaitDeadlineRead(t, endpoint, result)
		if readResult.err == nil {
			t.Fatalf("Read during close race returned payload %q without error", readResult.payload)
		}
	})
}

func startDeadlineRead(t *testing.T, endpoint *readDeadlineEndpoint) <-chan readDeadlineResult {
	t.Helper()
	started := make(chan struct{})
	result := make(chan readDeadlineResult, 1)
	go func() {
		close(started)
		payload, err := endpoint.read()
		result <- readDeadlineResult{payload: payload, err: err}
	}()
	select {
	case <-started:
	case <-time.After(deadlineReadTimeout):
		t.Fatal("read goroutine did not start")
	}
	return result
}

func assertDeadlineReadPending(t *testing.T, result <-chan readDeadlineResult, duration time.Duration) {
	t.Helper()
	if duration < 0 {
		duration = 0
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case got := <-result:
		t.Fatalf("read returned before pending interval elapsed: payload=%q err=%v", got.payload, got.err)
	case <-timer.C:
	}
}

func assertDeadlineResult(t *testing.T, endpoint *readDeadlineEndpoint, result <-chan readDeadlineResult, wantDeadline bool) {
	t.Helper()
	got := awaitDeadlineRead(t, endpoint, result)
	if wantDeadline && !errors.Is(got.err, deadlineError()) {
		t.Fatalf("read error = %v, want deadline exceeded", got.err)
	}
}

func deliverAndAssertRead(t *testing.T, endpoint *readDeadlineEndpoint, result <-chan readDeadlineResult) {
	t.Helper()
	payload := []byte("deadline-payload")
	if err := endpoint.deliver(payload); err != nil {
		_ = endpoint.close()
		t.Fatal(err)
	}
	got := awaitDeadlineRead(t, endpoint, result)
	if got.err != nil {
		t.Fatalf("read after deadline update = %v", got.err)
	}
	if string(got.payload) != string(payload) {
		t.Fatalf("read payload = %q, want %q", got.payload, payload)
	}
}

func awaitDeadlineRead(t *testing.T, endpoint *readDeadlineEndpoint, result <-chan readDeadlineResult) readDeadlineResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(deadlineReadTimeout):
		_ = endpoint.close()
		select {
		case <-result:
		case <-time.After(deadlineReadTimeout):
		}
		t.Fatal("blocked read did not return")
		return readDeadlineResult{}
	}
}

func awaitDeadlineOperation(t *testing.T, result <-chan error, name string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(deadlineReadTimeout):
		t.Fatalf("%s did not return", name)
		return nil
	}
}

type recordingReadDeadlineUplink struct {
	udpUplink
	mu       sync.Mutex
	deadline time.Time
}

func (u *recordingReadDeadlineUplink) SetReadDeadline(value time.Time) error {
	u.mu.Lock()
	u.deadline = value
	u.mu.Unlock()
	return u.udpUplink.SetReadDeadline(value)
}

func (u *recordingReadDeadlineUplink) observed(value time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.deadline.Equal(value)
}

type recordingReadDeadlineConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
}

func (c *recordingReadDeadlineConn) SetReadDeadline(value time.Time) error {
	c.mu.Lock()
	c.deadline = value
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(value)
}

func (c *recordingReadDeadlineConn) observed(value time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline.Equal(value)
}
