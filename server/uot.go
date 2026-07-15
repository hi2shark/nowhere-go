package server

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

// uotPacketConn adapts a typed UoT stream to net.PacketConn.
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
	for {
		frame, err := wire.ReadUOTFrame(c.Conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, nil, io.EOF
			}
			return 0, nil, err
		}
		switch frame.Kind {
		case wire.UOTFrameData:
			c.resetIdle()
			n = copy(p, frame.Payload)
			return n, c.destination, nil
		case wire.UOTFrameClose:
			return 0, nil, io.EOF
		case wire.UOTFrameReady, wire.UOTFrameReject:
			return 0, nil, wire.ErrInvalidUOTFrame
		default:
			return 0, nil, wire.ErrInvalidUOTFrame
		}
	}
}

func (c *uotPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	frame, err := wire.EncodeUOTFrame(wire.UOTFrame{Kind: wire.UOTFrameData, Payload: p})
	if err != nil {
		return 0, err
	}
	if _, err = c.Conn.Write(frame); err != nil {
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
		closeFrame, encErr := wire.EncodeUOTFrame(wire.UOTFrame{Kind: wire.UOTFrameClose})
		if encErr == nil {
			_, _ = c.Conn.Write(closeFrame)
		}
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

// writeUOTReady writes a typed UoT READY frame to the connection.
func writeUOTReady(w io.Writer) error {
	frame, err := wire.EncodeUOTFrame(wire.UOTFrame{Kind: wire.UOTFrameReady})
	if err != nil {
		return err
	}
	_, err = w.Write(frame)
	return err
}

// writeUOTReject writes a typed UoT REJECT frame with the given error code.
func writeUOTReject(w io.Writer, code wire.FlowErrorCode) error {
	frame, err := wire.EncodeUOTFrame(wire.UOTFrame{Kind: wire.UOTFrameReject, Code: code})
	if err != nil {
		return err
	}
	_, err = w.Write(frame)
	return err
}

// writeUOTClose writes a typed UoT CLOSE frame.
func writeUOTClose(w io.Writer) error {
	frame, err := wire.EncodeUOTFrame(wire.UOTFrame{Kind: wire.UOTFrameClose})
	if err != nil {
		return err
	}
	_, err = w.Write(frame)
	return err
}
