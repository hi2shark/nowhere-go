package server

import (
	"errors"
	"net"
	"sync"
	"time"
)

// pairedUDPConn exposes a pairedUDP as net.PacketConn.
type pairedUDPConn struct {
	flowID       uint64
	dest         net.Addr
	uplink       udpUplink
	downlink     udpDownlink
	compactLease *compactGenerationLease
	ackOnce      sync.Once
	ackErr       error
	closeOnce    sync.Once
	readDL       deadlineState
	writeDL      deadlineState
	idle         *time.Timer
	idleTimeout  time.Duration
	idleMu       sync.Mutex
	idleStarted  bool
	stateMu      sync.Mutex
	onFinish     func(error)
	bound        bool
	closed       bool
}

// newPairedUDPConn adapts a pairedUDP to net.PacketConn.
func newPairedUDPConn(paired *pairedUDP) *pairedUDPConn {
	down := paired.Downlink
	if q, ok := down.(*quicUDPDownlink); ok {
		down = &quicUDPDownlinkBound{flowID: paired.FlowID, send: q.send, lease: paired.compactLease}
	}
	conn := &pairedUDPConn{
		flowID:       paired.FlowID,
		dest:         parseTargetAddr(paired.Target),
		uplink:       paired.Uplink,
		downlink:     down,
		compactLease: paired.compactLease,
		idleTimeout:  paired.IdleTimeout,
	}
	if conn.idleTimeout <= 0 {
		conn.idleTimeout = DefaultUDPIdleTimeout
	}
	return conn
}

type addrString struct{ s string }

func (a *addrString) Network() string { return "udp" }
func (a *addrString) String() string  { return a.s }

func (c *pairedUDPConn) setFinish(onFinish func(error)) {
	c.stateMu.Lock()
	c.onFinish = onFinish
	c.stateMu.Unlock()
}

func (c *pairedUDPConn) bindToManager() bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.closed || c.onFinish == nil {
		return false
	}
	c.bound = true
	return true
}

func (c *pairedUDPConn) sendAck() error {
	c.ackOnce.Do(func() {
		if err := c.downlink.WriteAck(c.flowID); err != nil {
			c.ackErr = err
			return
		}
		if downlink, ok := c.downlink.(*quicUDPDownlinkBound); ok && downlink.lease != nil && downlink.lease == c.compactLease {
			return
		}
		if c.compactLease != nil {
			c.ackErr = c.compactLease.SendOpenAck()
		}
	})
	return c.ackErr
}

func (c *pairedUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.readDL.expired(time.Now()) {
		return 0, nil, deadlineError()
	}
	for {
		payload, err := c.uplink.ReadPacket()
		if err != nil {
			return 0, nil, err
		}
		if len(payload) == 0 {
			continue
		}
		if err := c.sendAck(); err != nil {
			if errors.Is(err, errCompactAckRevoked) {
				return 0, nil, net.ErrClosed
			}
			c.closeWithError(err)
			return 0, nil, err
		}
		c.resetIdle()
		n = copy(p, payload)
		return n, c.dest, nil
	}
}

func (c *pairedUDPConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	if c.writeDL.expired(time.Now()) {
		return 0, deadlineError()
	}
	if err := c.downlink.WritePacket(p); err != nil {
		return 0, err
	}
	c.resetIdle()
	return len(p), nil
}

func (c *pairedUDPConn) Close() error {
	c.closeWithError(nil)
	return nil
}

func (c *pairedUDPConn) closeWithError(cause error) {
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return
	}
	if c.bound && c.onFinish != nil {
		onFinish := c.onFinish
		c.stateMu.Unlock()
		onFinish(cause)
		return
	}
	c.closed = true
	c.stateMu.Unlock()
	c.closePhysical(cause)
}

func (c *pairedUDPConn) closeFromManager(cause error) {
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return
	}
	c.closed = true
	c.stateMu.Unlock()
	c.closePhysical(cause)
}

func (c *pairedUDPConn) closePhysical(cause error) {
	c.closeOnce.Do(func() {
		c.idleMu.Lock()
		if c.idle != nil {
			c.idle.Stop()
		}
		c.idle = nil
		c.idleStarted = false
		c.idleMu.Unlock()
		if _, isTCP := c.downlink.(*tcpUDPDownlink); !isTCP {
			_ = c.downlink.WriteClose(c.flowID)
		}
		closeUDPHalfWithError(udpHalf{Uplink: c.uplink, Downlink: c.downlink}, cause)
		if c.compactLease != nil {
			c.compactLease.MarkCleanupDone()
		}
	})
}

func (c *pairedUDPConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (c *pairedUDPConn) SetDeadline(value time.Time) error {
	if err := c.SetReadDeadline(value); err != nil {
		return err
	}
	return c.SetWriteDeadline(value)
}
func (c *pairedUDPConn) SetReadDeadline(value time.Time) error {
	c.readDL.set(value)
	return c.uplink.SetReadDeadline(value)
}
func (c *pairedUDPConn) SetWriteDeadline(value time.Time) error {
	c.writeDL.set(value)
	if deadline, ok := c.downlink.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return deadline.SetWriteDeadline(value)
	}
	return nil
}

func (c *pairedUDPConn) startIdle() bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if !c.bound || c.closed {
		return false
	}
	c.idleMu.Lock()
	defer c.idleMu.Unlock()
	if c.idleStarted {
		return true
	}
	c.idleStarted = true
	c.idle = time.AfterFunc(c.idleTimeout, func() { _ = c.Close() })
	return true
}

func (c *pairedUDPConn) resetIdle() {
	c.idleMu.Lock()
	defer c.idleMu.Unlock()
	if !c.idleStarted {
		return
	}
	if c.idle != nil {
		c.idle.Stop()
	}
	c.idle = time.AfterFunc(c.idleTimeout, func() { _ = c.Close() })
}

var _ net.PacketConn = (*pairedUDPConn)(nil)
