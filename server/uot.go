package server

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

// uotPacketConn adapts a Nowhere length-prefixed UoT stream to net.PacketConn.
type uotPacketConn struct {
	net.Conn
	destination net.Addr
	readMu      sync.Mutex
	writeMu     sync.Mutex
	idleMu      sync.Mutex
	idle        *time.Timer
	idleTimeout time.Duration
	closeOnce   sync.Once
}

// newUOTPacketConn wraps conn; destination is returned from ReadFrom.
func newUOTPacketConn(conn net.Conn, destination net.Addr) *uotPacketConn {
	if destination == nil {
		destination = &net.UDPAddr{}
	}
	packetConn := &uotPacketConn{Conn: conn, destination: destination, idleTimeout: DefaultUDPIdleTimeout}
	packetConn.resetIdle()
	return packetConn
}

func (c *uotPacketConn) SetIdleTimeout(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	c.idleMu.Lock()
	c.idleTimeout = timeout
	c.idleMu.Unlock()
	c.resetIdle()
}

func (c *uotPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var length uint16
	if err = binary.Read(c.Conn, binary.BigEndian, &length); err != nil {
		return
	}
	if int(length) > len(p) {
		// Drain oversized frame then report short buffer.
		tmp := make([]byte, length)
		if _, err = io.ReadFull(c.Conn, tmp); err != nil {
			return
		}
		n = copy(p, tmp)
		return n, c.destination, io.ErrShortBuffer
	}
	if _, err = io.ReadFull(c.Conn, p[:length]); err != nil {
		return
	}
	c.resetIdle()
	return int(length), c.destination, nil
}

func (c *uotPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	frame, err := wire.WriteUOTPacketFrame(p)
	if err != nil {
		return 0, err
	}
	_, err = c.Conn.Write(frame)
	if err != nil {
		return 0, err
	}
	c.resetIdle()
	return len(p), nil
}

func (c *uotPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.idleMu.Lock()
		if c.idle != nil {
			c.idle.Stop()
		}
		c.idleMu.Unlock()
		err = c.Conn.Close()
	})
	return err
}

func (c *uotPacketConn) closeWithError(cause error) {
	c.closeOnce.Do(func() {
		c.idleMu.Lock()
		if c.idle != nil {
			c.idle.Stop()
		}
		c.idleMu.Unlock()
		closeConnWithError(c.Conn, cause)
	})
}

func (c *uotPacketConn) resetIdle() {
	c.idleMu.Lock()
	defer c.idleMu.Unlock()
	if c.idle != nil {
		c.idle.Stop()
	}
	c.idle = time.AfterFunc(c.idleTimeout, func() { _ = c.Close() })
}

func (c *uotPacketConn) LocalAddr() net.Addr {
	if c.Conn.LocalAddr() != nil {
		return c.Conn.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (c *uotPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *uotPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *uotPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

var (
	_ net.PacketConn = (*uotPacketConn)(nil)
	_ io.Closer      = (*uotPacketConn)(nil)
)
