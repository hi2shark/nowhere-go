package server

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

type legacyUDPFlow struct {
	session *portalSession
	key     legacyUDPKey
	dest    net.Addr
	waiter  chan []byte
	done    chan struct{}

	readDL  deadlineState
	writeDL deadlineState

	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	closeErr  error
	idle      *time.Timer
}

func newLegacyUDPFlow(session *portalSession, key legacyUDPKey) *legacyUDPFlow {
	return &legacyUDPFlow{
		session: session,
		key:     key,
		dest:    parseTargetAddr(key.target),
		waiter:  make(chan []byte, session.Handler.config.limits.QUICQueuePackets),
		done:    make(chan struct{}),
	}
}

func (f *legacyUDPFlow) deliver(payload []byte) {
	if !f.session.reserveQueueBytes(len(payload)) {
		return
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		f.session.releaseQueueBytes(len(payload))
		return
	}
	copyPayload := append([]byte(nil), payload...)
	select {
	case f.waiter <- copyPayload:
		f.mu.Unlock()
		f.resetIdle()
	default:
		f.mu.Unlock()
		f.session.releaseQueueBytes(len(copyPayload))
	}
}

func (f *legacyUDPFlow) shutdown(err error) {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.closeErr = err
		if f.idle != nil {
			f.idle.Stop()
		}
		f.mu.Unlock()
		close(f.done)
		for {
			select {
			case payload := <-f.waiter:
				f.session.releaseQueueBytes(len(payload))
			default:
				f.session.detachLegacyFlow(f.key, f)
				return
			}
		}
	})
}

func (f *legacyUDPFlow) ReadFrom(buffer []byte) (n int, addr net.Addr, err error) {
	for {
		wait, expired := f.readDL.newReadWait(time.Now())
		if expired {
			return 0, nil, deadlineError()
		}
		select {
		case payload := <-f.waiter:
			wait.stop()
			f.session.releaseQueueBytes(len(payload))
			f.resetIdle()
			return copy(buffer, payload), f.dest, nil
		case <-f.done:
			wait.stop()
			return 0, nil, f.err()
		case <-wait.changed:
			wait.stop()
		case <-wait.timerC:
			if wait.timerExpired(time.Now()) {
				return 0, nil, deadlineError()
			}
		}
	}
}

func (f *legacyUDPFlow) WriteTo(payload []byte, _ net.Addr) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	select {
	case <-f.done:
		return 0, f.err()
	default:
	}
	if f.writeDL.expired(time.Now()) {
		return 0, deadlineError()
	}
	frame, err := wire.EncodeUDPDatagram(
		wire.UDPTypeResponse,
		f.key.flowID,
		f.key.target,
		payload,
		f.session.Handler.config.spec,
	)
	if err != nil {
		return 0, err
	}
	if err := f.session.SendDatagram(frame); err != nil {
		return 0, err
	}
	f.resetIdle()
	return len(payload), nil
}

func (f *legacyUDPFlow) Close() error {
	f.shutdown(net.ErrClosed)
	return nil
}

func (f *legacyUDPFlow) LocalAddr() net.Addr {
	if f.session != nil && f.session.Conn != nil {
		return f.session.Conn.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (f *legacyUDPFlow) SetDeadline(value time.Time) error {
	f.readDL.set(value)
	f.writeDL.set(value)
	return nil
}

func (f *legacyUDPFlow) SetReadDeadline(value time.Time) error {
	f.readDL.set(value)
	return nil
}

func (f *legacyUDPFlow) SetWriteDeadline(value time.Time) error {
	f.writeDL.set(value)
	return nil
}

func (f *legacyUDPFlow) resetIdle() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	if f.idle != nil {
		f.idle.Stop()
	}
	timeout := f.session.Handler.config.timeouts.UDPIdle
	f.idle = time.AfterFunc(timeout, func() { f.shutdown(context.DeadlineExceeded) })
	f.mu.Unlock()
}

func (f *legacyUDPFlow) err() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closeErr != nil {
		return f.closeErr
	}
	return io.EOF
}

var _ net.PacketConn = (*legacyUDPFlow)(nil)
