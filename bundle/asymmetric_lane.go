package bundle

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/wire"
)

// udpUplink is the write side of a UDP logical flow.
type udpUplink interface {
	WritePacket(p []byte) (int, error)
	ClosePacket() error
}

// udpDownlink is the read side of a UDP logical flow.
type udpDownlink interface {
	ReadPacket(p []byte) (int, error)
	ClosePacket() error
}

// uotStreamWriter serializes DATA and the best-effort CLOSE attempt. Close
// never waits behind a blocked DATA write; closing the conn releases that write.
type uotStreamWriter struct {
	conn      net.Conn
	mu        sync.Mutex
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func (w *uotStreamWriter) WritePacket(p []byte) (int, error) {
	if w.closed.Load() {
		return 0, net.ErrClosed
	}
	frame, err := wire.EncodeUOTFrame(wire.UOTFrame{Kind: wire.UOTFrameData, Payload: p})
	if err != nil {
		return 0, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return 0, net.ErrClosed
	}
	if _, err := w.conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *uotStreamWriter) Close() error {
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		if w.mu.TryLock() {
			_ = w.conn.SetWriteDeadline(time.Now())
			if closeFrame, err := wire.EncodeUOTFrame(wire.UOTFrame{Kind: wire.UOTFrameClose}); err == nil {
				_, _ = w.conn.Write(closeFrame)
			}
			w.mu.Unlock()
		}
		w.closeErr = w.conn.Close()
	})
	return w.closeErr
}

// uotPacketConn adapts a typed UoT stream to net.PacketConn.
type uotPacketConn struct {
	conn        net.Conn
	destination net.Addr
	readMu      sync.Mutex
	writerOnce  sync.Once
	writer      *uotStreamWriter
}

func newUOTPacketConn(conn net.Conn, destination net.Addr) *uotPacketConn {
	if destination == nil {
		destination = &net.UDPAddr{}
	}
	return &uotPacketConn{conn: conn, destination: destination}
}

func (c *uotPacketConn) streamWriter() *uotStreamWriter {
	c.writerOnce.Do(func() {
		c.writer = &uotStreamWriter{conn: c.conn}
	})
	return c.writer
}

func (c *uotPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	frame, err := wire.ReadUOTFrame(c.conn)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil, io.EOF
		}
		return 0, nil, err
	}
	switch frame.Kind {
	case wire.UOTFrameData:
		n = copy(p, frame.Payload)
		return n, c.destination, nil
	case wire.UOTFrameClose:
		return 0, nil, io.EOF
	default:
		return 0, nil, wire.ErrInvalidUOTFrame
	}
}

func (c *uotPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.streamWriter().WritePacket(p)
}

func (c *uotPacketConn) Close() error {
	return c.streamWriter().Close()
}

func (c *uotPacketConn) LocalAddr() net.Addr {
	if c.conn.LocalAddr() != nil {
		return c.conn.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (c *uotPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *uotPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *uotPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

var _ net.PacketConn = (*uotPacketConn)(nil)

// parseTargetAddr parses a host:port target into a net.Addr.
func parseTargetAddr(target string) net.Addr {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return &net.UDPAddr{}
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return &net.UDPAddr{}
	}
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: port}
}

// quicPacketConn adapts a QUIC UDP logical flow (control stream + datagrams) to net.PacketConn.
type quicPacketConn struct {
	session      *qSessionHandle
	control      net.Conn
	flowID       uint64
	destination  net.Addr
	readMu       sync.Mutex
	writeMu      sync.Mutex
	closeOnce    sync.Once
	nextPacketID atomic.Uint32
}

type qSessionHandle struct {
	quic          *quicPreparedStream
	flow          *quicDatagramFlow
	flowID        uint64
	setupErr      error
	closed        atomic.Bool
	signalOnce    sync.Once
	done          chan struct{}
	readDeadline  *datagramDeadline
	writeDeadline *datagramDeadline
}

func newQSessionHandle(prep *quicPreparedStream, flow *quicDatagramFlow, flowID uint64, setupErr error) *qSessionHandle {
	return &qSessionHandle{
		quic:          prep,
		flow:          flow,
		flowID:        flowID,
		setupErr:      setupErr,
		done:          make(chan struct{}),
		readDeadline:  newDatagramDeadline(),
		writeDeadline: newDatagramDeadline(),
	}
}

func newQUICDatagramHandle(prep *quicPreparedStream, flowID uint64) (*qSessionHandle, error) {
	if prep == nil || prep.session == nil {
		return nil, errors.New("nowhere: nil quic session")
	}
	session, ok := prep.session.(*quicSessionMux)
	if !ok {
		return nil, errors.New("nowhere: quic session is not bundle managed")
	}
	flow, err := session.register(flowID)
	if err != nil {
		return nil, err
	}
	return newQSessionHandle(prep, flow, flowID, nil), nil
}

func newQUICSendHandle(prep *quicPreparedStream, flowID uint64) *qSessionHandle {
	return newQSessionHandle(prep, nil, flowID, nil)
}

func newQUICPacketConn(prep *quicPreparedStream, control net.Conn, dest string) *quicPacketConn {
	flowID := uint64(0)
	if prep != nil {
		flowID = prep.flowID()
	}
	handle, err := newQUICDatagramHandle(prep, flowID)
	if err != nil {
		handle = newQSessionHandle(prep, nil, flowID, err)
	}
	return &quicPacketConn{
		session:     handle,
		control:     control,
		flowID:      flowID,
		destination: parseTargetAddr(dest),
	}
}

func (c *quicPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	payload, err := c.session.readPacket(context.Background())
	if err != nil {
		return 0, nil, err
	}
	return copy(p, payload), c.destination, nil
}

func (c *quicPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeQUICUDPPacket(c.session, c.flowID, &c.nextPacketID, p)
}

func writeQUICUDPPacket(session *qSessionHandle, flowID uint64, nextPacketID *atomic.Uint32, payload []byte) (int, error) {
	if err := session.stateError(); err != nil {
		return 0, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		packetID := nextPacketID.Add(1)
		if packetID == 0 {
			packetID = nextPacketID.Add(1)
		}
		frames, err := wire.EncodeUDPDataFragments(flowID, packetID, payload, session.quic.MaxDatagramSize())
		if err != nil {
			return 0, err
		}
		retry := false
		for _, frame := range frames {
			if err := session.sendDatagram(frame); err != nil {
				var tooLarge *quic.DatagramTooLargeError
				if !errors.As(err, &tooLarge) {
					return 0, err
				}
				if attempt == 0 {
					retry = true
					break
				}
				return len(payload), nil
			}
		}
		if retry {
			continue
		}
		return len(payload), nil
	}
	return len(payload), nil
}

func (c *quicPacketConn) Close() (err error) {
	c.closeOnce.Do(func() {
		err = c.session.closePacket()
		if c.control != nil {
			if closeErr := c.control.Close(); err == nil {
				err = closeErr
			}
		}
	})
	return err
}

func (c *quicPacketConn) LocalAddr() net.Addr {
	if c.session != nil && c.session.quic != nil {
		return c.session.quic.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (c *quicPacketConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *quicPacketConn) SetReadDeadline(t time.Time) error {
	if err := c.session.setReadDeadline(t); err != nil {
		return err
	}
	if c.control != nil {
		return c.control.SetReadDeadline(t)
	}
	return nil
}

func (c *quicPacketConn) SetWriteDeadline(t time.Time) error {
	if err := c.session.setWriteDeadline(t); err != nil {
		return err
	}
	if c.control != nil {
		return c.control.SetWriteDeadline(t)
	}
	return nil
}

func (h *qSessionHandle) doneSignal() <-chan struct{} {
	h.signalOnce.Do(func() {
		if h.done == nil {
			h.done = make(chan struct{})
		}
		if h.closed.Load() {
			close(h.done)
		}
	})
	return h.done
}

func (h *qSessionHandle) markClosed() bool {
	if h == nil || h.closed.Swap(true) {
		return false
	}
	done := h.doneSignal()
	select {
	case <-done:
	default:
		close(h.done)
	}
	return true
}

func (h *qSessionHandle) setReadDeadline(t time.Time) error {
	if h == nil || h.closed.Load() {
		return net.ErrClosed
	}
	if err := h.readDeadline.set(t); err != nil {
		return err
	}
	if h.closed.Load() {
		h.readDeadline.close()
		return net.ErrClosed
	}
	return nil
}

func (h *qSessionHandle) setWriteDeadline(t time.Time) error {
	if h == nil || h.closed.Load() {
		return net.ErrClosed
	}
	if err := h.writeDeadline.set(t); err != nil {
		return err
	}
	if h.closed.Load() {
		h.writeDeadline.close()
		return net.ErrClosed
	}
	return nil
}

func (h *qSessionHandle) readPacket(ctx context.Context) ([]byte, error) {
	if h == nil {
		return nil, net.ErrClosed
	}
	if h.setupErr != nil {
		return nil, h.setupErr
	}
	if h.closed.Load() {
		return nil, net.ErrClosed
	}
	if h.flow == nil {
		return nil, errors.New("nowhere: quic udp flow is not registered")
	}
	return h.flow.readPacket(ctx, h.readDeadline)
}

func (h *qSessionHandle) stateError() error {
	if h == nil {
		return net.ErrClosed
	}
	if h.setupErr != nil {
		return h.setupErr
	}
	if h.closed.Load() {
		return net.ErrClosed
	}
	if h.flow != nil {
		select {
		case <-h.flow.done:
			return h.flow.closeCause()
		default:
		}
	}
	return nil
}

func (h *qSessionHandle) sendDatagram(frame []byte) error {
	if err := h.stateError(); err != nil {
		return err
	}
	if h.writeDeadline.expired() {
		return errDatagramDeadline
	}
	if h.quic == nil || h.quic.session == nil {
		return net.ErrClosed
	}
	if session, ok := h.quic.session.(*quicSessionMux); ok {
		return session.sendDatagram(h, frame, h.writeDeadline)
	}
	if err := h.quic.SendDatagram(frame); err != nil {
		return err
	}
	if h.writeDeadline.expired() {
		return errDatagramDeadline
	}
	return nil
}

func (h *qSessionHandle) closePacket() error {
	if !h.markClosed() {
		return nil
	}
	h.readDeadline.close()
	h.writeDeadline.close()
	if h.flow != nil {
		h.flow.unregister(net.ErrClosed)
	}
	if h.quic == nil || h.quic.session == nil || h.flowID == 0 {
		return nil
	}
	closeFrame, err := wire.EncodeUDPClose(h.flowID)
	if err != nil {
		return err
	}
	if session, ok := h.quic.session.(*quicSessionMux); ok {
		return session.enqueueClose(closeFrame)
	}
	return nil
}

var _ net.PacketConn = (*quicPacketConn)(nil)

const nowuDataHeaderLen = 4 + 1 + 8 + 4 + 1 + 1 + 2

// flowIDer lets a prepared stream expose its flow id for datagram routing.
type flowIDer interface {
	flowID() uint64
}

var _ flowIDer = (*quicPreparedStream)(nil)
