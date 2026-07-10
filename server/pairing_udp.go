package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/go-nowhere/wire"
)

// udpHalf is one side of an asymmetric UDP flow.
type udpHalf struct {
	Role       wire.FlowRole
	Uplink     udpUplink
	Downlink   udpDownlink
	compactAck compactAck
}

type udpUplink interface {
	ReadPacket() ([]byte, error)
	Close() error
}

type udpDownlink interface {
	WritePacket(p []byte) error
	WriteAck(flowID uint64) error
	WriteClose(flowID uint64) error
	Close() error
}

// compactAck sends OPEN_ACK on the QUIC uplink session when present.
type compactAck interface {
	SendOpenAck(flowID uint64) error
	MarkAcked()
}

// pairedUDP is a completed asymmetric UDP flow ready for routing.
type pairedUDP struct {
	FlowID      uint64
	Target      string
	Uplink      udpUplink
	Downlink    udpDownlink
	compactAck  compactAck
	IdleTimeout time.Duration
}

// SubmitUDP caches or pairs a UDP half. Completing half returns *pairedUDP;
// waiting half returns (nil, nil).
func (m *flowPairManager) SubmitUDP(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target string, half udpHalf) (*pairedUDP, error) {
	if err := validatePairHeader(header, wire.FlowKindUDP); err != nil {
		return nil, err
	}
	pending := &pendingFlow{
		meta: metadataFrom(header, target), role: half.Role, udp: half,
		done: make(chan struct{}), state: pairWaiting,
	}
	key := pairKey{session: sessionID, flowID: header.FlowID}
	existing, err := m.submit(key, pending)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		var uplink udpUplink
		var downlink udpDownlink
		var ack compactAck
		if half.Role == wire.FlowRoleOpen {
			uplink, downlink = half.Uplink, existing.udp.Downlink
			ack = half.compactAck
			if ack == nil {
				ack = existing.udp.compactAck
			}
		} else {
			uplink, downlink = existing.udp.Uplink, half.Downlink
			ack = existing.udp.compactAck
			if ack == nil {
				ack = half.compactAck
			}
		}
		return &pairedUDP{
			FlowID:     header.FlowID,
			Target:     target,
			Uplink:     uplink,
			Downlink:   downlink,
			compactAck: ack,
		}, nil
	}
	return nil, m.wait(ctx, key, pending)
}

func closeUDPHalfWithError(half udpHalf, err error) {
	if half.Uplink != nil {
		if value, ok := half.Uplink.(*tcpUDPUplink); ok {
			closeConnWithError(value.conn, err)
		} else {
			_ = half.Uplink.Close()
		}
	}
	if half.Downlink != nil {
		if value, ok := half.Downlink.(*tcpUDPDownlink); ok {
			closeConnWithError(value.conn, err)
		} else {
			_ = half.Downlink.Close()
		}
	}
}

// --- TCP UoT halves ---

type tcpUDPUplink struct {
	conn net.Conn
	mu   sync.Mutex
}

func newTCPUDPUplink(conn net.Conn) udpUplink { return &tcpUDPUplink{conn: conn} }

func (u *tcpUDPUplink) ReadPacket() ([]byte, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	var lenBuf [2]byte
	if _, err := io.ReadFull(u.conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(u.conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (u *tcpUDPUplink) Close() error { return u.conn.Close() }

type tcpUDPDownlink struct {
	conn net.Conn
	mu   sync.Mutex
}

func newTCPUDPDownlink(conn net.Conn) udpDownlink { return &tcpUDPDownlink{conn: conn} }

func (d *tcpUDPDownlink) WritePacket(p []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	frame, err := wire.WriteUOTPacketFrame(p)
	if err != nil {
		return err
	}
	_, err = d.conn.Write(frame)
	return err
}

func (d *tcpUDPDownlink) WriteAck(_ uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Write([]byte{0, 0})
	return err
}

func (d *tcpUDPDownlink) WriteClose(_ uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.conn.Write([]byte{0, 0})
	return err
}

func (d *tcpUDPDownlink) Close() error { return d.conn.Close() }

// --- QUIC DATAGRAM halves ---

// quicUDPUplink buffers DATAGRAM payloads for an asymmetric UDP OPEN half.
type quicUDPUplink struct {
	ch      chan []byte
	closed  chan struct{}
	once    sync.Once
	mu      sync.Mutex
	session *portalSession
	onClose func()
	readDL  deadlineSignal
}

func newQUICUDPUplink(session *portalSession) *quicUDPUplink {
	queuePackets := DefaultQUICQueuePackets
	if session != nil && session.Handler != nil {
		queuePackets = session.Handler.config.limits.QUICQueuePackets
	}
	return &quicUDPUplink{
		ch:      make(chan []byte, queuePackets),
		closed:  make(chan struct{}),
		session: session,
	}
}

func (u *quicUDPUplink) Deliver(p []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	select {
	case <-u.closed:
		return
	default:
	}
	if u.session != nil && !u.session.reserveQueueBytes(len(p)) {
		return
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case u.ch <- cp:
	default:
		if u.session != nil {
			u.session.releaseQueueBytes(len(cp))
		}
	}
}

func (u *quicUDPUplink) ReadPacket() ([]byte, error) {
	select {
	case p := <-u.ch:
		if u.session != nil {
			u.session.releaseQueueBytes(len(p))
		}
		return p, nil
	case <-u.closed:
		return nil, io.EOF
	case <-u.readDL.wait():
		return nil, deadlineError()
	}
}

func (u *quicUDPUplink) Close() error {
	u.once.Do(func() {
		u.mu.Lock()
		defer u.mu.Unlock()
		close(u.closed)
		for {
			select {
			case payload := <-u.ch:
				if u.session != nil {
					u.session.releaseQueueBytes(len(payload))
				}
			default:
				if u.onClose != nil {
					u.onClose()
				}
				return
			}
		}
	})
	return nil
}

func (u *quicUDPUplink) SetReadDeadline(value time.Time) error {
	u.readDL.set(value)
	return nil
}

type quicUDPDownlink struct {
	send func([]byte) error
}

func newQUICUDPDownlink(send func([]byte) error) udpDownlink {
	return &quicUDPDownlink{send: send}
}

func (d *quicUDPDownlink) WritePacket(p []byte) error {
	return fmt.Errorf("nowhere: quic downlink WritePacket requires paired wrapper")
}

func (d *quicUDPDownlink) WriteAck(flowID uint64) error {
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeOpenAck, flowID, nil)
	if err != nil {
		return err
	}
	return d.send(frame)
}

func (d *quicUDPDownlink) WriteClose(flowID uint64) error {
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeCompactClose, flowID, nil)
	if err != nil {
		return err
	}
	return d.send(frame)
}

func (d *quicUDPDownlink) Close() error { return nil }

type quicUDPDownlinkBound struct {
	flowID uint64
	send   func([]byte) error
}

func (d *quicUDPDownlinkBound) WritePacket(p []byte) error {
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeData, d.flowID, p)
	if err != nil {
		return err
	}
	return d.send(frame)
}

func (d *quicUDPDownlinkBound) WriteAck(flowID uint64) error {
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeOpenAck, flowID, nil)
	if err != nil {
		return err
	}
	return d.send(frame)
}

func (d *quicUDPDownlinkBound) WriteClose(flowID uint64) error {
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeCompactClose, flowID, nil)
	if err != nil {
		return err
	}
	return d.send(frame)
}

func (d *quicUDPDownlinkBound) Close() error { return nil }

type quicCompactAck struct {
	send  func([]byte) error
	mark  func()
	mu    sync.Mutex
	acked bool
}

func newQUICCompactAck(send func([]byte) error, mark func()) compactAck {
	return &quicCompactAck{send: send, mark: mark}
}

func (a *quicCompactAck) SendOpenAck(flowID uint64) error {
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeOpenAck, flowID, nil)
	if err != nil {
		return err
	}
	if err := a.send(frame); err != nil {
		return err
	}
	a.MarkAcked()
	return nil
}

func (a *quicCompactAck) MarkAcked() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.acked {
		return
	}
	a.acked = true
	if a.mark != nil {
		a.mark()
	}
}

// pairedUDPConn exposes a pairedUDP as net.PacketConn.
type pairedUDPConn struct {
	flowID      uint64
	dest        net.Addr
	uplink      udpUplink
	downlink    udpDownlink
	compactAck  compactAck
	ackOnce     sync.Once
	closeOnce   sync.Once
	readDL      deadlineSignal
	writeDL     deadlineSignal
	idle        *time.Timer
	idleTimeout time.Duration
	idleMu      sync.Mutex
}

// newPairedUDPConn adapts a pairedUDP to net.PacketConn.
func newPairedUDPConn(paired *pairedUDP) net.PacketConn {
	down := paired.Downlink
	if q, ok := down.(*quicUDPDownlink); ok {
		down = &quicUDPDownlinkBound{flowID: paired.FlowID, send: q.send}
	}
	dest := parseTargetAddr(paired.Target)
	conn := &pairedUDPConn{
		flowID:      paired.FlowID,
		dest:        dest,
		uplink:      paired.Uplink,
		downlink:    down,
		compactAck:  paired.compactAck,
		idleTimeout: paired.IdleTimeout,
	}
	if conn.idleTimeout <= 0 {
		conn.idleTimeout = DefaultUDPIdleTimeout
	}
	conn.resetIdle()
	return conn
}

type addrString struct{ s string }

func (a *addrString) Network() string { return "udp" }
func (a *addrString) String() string  { return a.s }

func (c *pairedUDPConn) sendAck() {
	c.ackOnce.Do(func() {
		_ = c.downlink.WriteAck(c.flowID)
		if c.compactAck != nil {
			_ = c.compactAck.SendOpenAck(c.flowID)
		}
	})
}

func (c *pairedUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case <-c.readDL.wait():
		return 0, nil, deadlineError()
	default:
	}
	for {
		payload, err := c.uplink.ReadPacket()
		if err != nil {
			return 0, nil, err
		}
		if len(payload) == 0 {
			continue
		}
		c.sendAck()
		c.resetIdle()
		n = copy(p, payload)
		return n, c.dest, nil
	}
}

func (c *pairedUDPConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	select {
	case <-c.writeDL.wait():
		return 0, deadlineError()
	default:
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
	c.closeOnce.Do(func() {
		c.idleMu.Lock()
		if c.idle != nil {
			c.idle.Stop()
		}
		c.idleMu.Unlock()
		_ = c.downlink.WriteClose(c.flowID)
		closeUDPHalfWithError(udpHalf{Uplink: c.uplink, Downlink: c.downlink}, cause)
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
	if deadline, ok := c.uplink.(interface{ SetReadDeadline(time.Time) error }); ok {
		return deadline.SetReadDeadline(value)
	}
	return nil
}
func (c *pairedUDPConn) SetWriteDeadline(value time.Time) error {
	c.writeDL.set(value)
	if deadline, ok := c.downlink.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return deadline.SetWriteDeadline(value)
	}
	return nil
}

func (c *pairedUDPConn) resetIdle() {
	c.idleMu.Lock()
	defer c.idleMu.Unlock()
	if c.idle != nil {
		c.idle.Stop()
	}
	c.idle = time.AfterFunc(c.idleTimeout, func() { _ = c.Close() })
}

var _ net.PacketConn = (*pairedUDPConn)(nil)
