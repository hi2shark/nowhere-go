package server

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/go-nowhere/wire"
)

// UOTPacketConn adapts a Nowhere length-prefixed UoT stream to net.PacketConn.
type UOTPacketConn struct {
	net.Conn
	destination net.Addr
	readMu      sync.Mutex
	writeMu     sync.Mutex
}

// NewUOTPacketConn wraps conn; destination is returned from ReadFrom.
func NewUOTPacketConn(conn net.Conn, destination net.Addr) *UOTPacketConn {
	if destination == nil {
		destination = &net.UDPAddr{}
	}
	return &UOTPacketConn{Conn: conn, destination: destination}
}

func (c *UOTPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
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
	return int(length), c.destination, nil
}

func (c *UOTPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
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
	return len(p), nil
}

func (c *UOTPacketConn) LocalAddr() net.Addr {
	if c.Conn.LocalAddr() != nil {
		return c.Conn.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (c *UOTPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *UOTPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *UOTPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

var (
	_ net.PacketConn = (*UOTPacketConn)(nil)
	_ io.Closer      = (*UOTPacketConn)(nil)
)
