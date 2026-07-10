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

// UDPHalf is one side of an asymmetric UDP flow.
type UDPHalf struct {
	Role       wire.FlowRole
	Uplink     UDPUplink
	Downlink   UDPDownlink
	CompactAck CompactAck
}

type UDPUplink interface {
	ReadPacket() ([]byte, error)
	Close() error
}

type UDPDownlink interface {
	WritePacket(p []byte) error
	WriteAck(flowID uint64) error
	WriteClose(flowID uint64) error
	Close() error
}

// CompactAck sends OPEN_ACK on the QUIC uplink session when present.
type CompactAck interface {
	SendOpenAck(flowID uint64) error
	MarkAcked()
}

type pendingUDPHalf struct {
	role       wire.FlowRole
	uplink     UDPUplink
	downlink   UDPDownlink
	compactAck CompactAck
	timer      *time.Timer
	done       chan struct{}
	timedOut   bool
}

// PairedUDP is a completed asymmetric UDP flow ready for routing.
type PairedUDP struct {
	FlowID     uint64
	Target     string
	Uplink     UDPUplink
	Downlink   UDPDownlink
	CompactAck CompactAck
}

// SubmitUDP caches or pairs a UDP half. Completing half returns *PairedUDP;
// waiting half returns (nil, nil).
func (m *FlowPairManager) SubmitUDP(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target string, half UDPHalf) (*PairedUDP, error) {
	if header.Kind != wire.FlowKindUDP {
		return nil, fmt.Errorf("nowhere: SubmitUDP requires FlowKindUDP")
	}
	if header.Uplink == header.Downlink {
		return nil, fmt.Errorf("nowhere: symmetric carriers must not use flow envelope")
	}
	key := flowKey{
		session: sessionID,
		flowID:  header.FlowID,
		kind:    header.Kind,
		target:  target,
		up:      header.Uplink,
		down:    header.Downlink,
	}

	m.mu.Lock()
	if existing, ok := m.pendingUDP[key]; ok {
		if existing.role == half.Role {
			m.mu.Unlock()
			closeUDPHalf(half)
			return nil, fmt.Errorf("nowhere: duplicate udp flow half role=%d", half.Role)
		}
		delete(m.pendingUDP, key)
		if existing.timer != nil {
			existing.timer.Stop()
		}
		var uplink UDPUplink
		var downlink UDPDownlink
		var ack CompactAck
		if half.Role == wire.FlowRoleOpen {
			uplink, downlink = half.Uplink, existing.downlink
			ack = half.CompactAck
			if ack == nil {
				ack = existing.compactAck
			}
		} else {
			uplink, downlink = existing.uplink, half.Downlink
			ack = existing.compactAck
			if ack == nil {
				ack = half.CompactAck
			}
		}
		close(existing.done)
		m.mu.Unlock()
		return &PairedUDP{
			FlowID:     header.FlowID,
			Target:     target,
			Uplink:     uplink,
			Downlink:   downlink,
			CompactAck: ack,
		}, nil
	}

	pending := &pendingUDPHalf{
		role:       half.Role,
		uplink:     half.Uplink,
		downlink:   half.Downlink,
		compactAck: half.CompactAck,
		done:       make(chan struct{}),
	}
	pending.timer = time.AfterFunc(m.timeout, func() {
		m.mu.Lock()
		cur, ok := m.pendingUDP[key]
		if !ok || cur != pending {
			m.mu.Unlock()
			return
		}
		delete(m.pendingUDP, key)
		pending.timedOut = true
		m.mu.Unlock()
		closeUDPHalf(UDPHalf{Role: pending.role, Uplink: pending.uplink, Downlink: pending.downlink})
		close(pending.done)
	})
	if m.pendingUDP == nil {
		m.pendingUDP = make(map[flowKey]*pendingUDPHalf)
	}
	m.pendingUDP[key] = pending
	m.mu.Unlock()

	select {
	case <-pending.done:
		if pending.timedOut {
			return nil, fmt.Errorf("nowhere: udp flow pair timeout")
		}
		return nil, nil
	case <-ctx.Done():
		owned := false
		m.mu.Lock()
		if cur, ok := m.pendingUDP[key]; ok && cur == pending {
			delete(m.pendingUDP, key)
			if pending.timer != nil {
				pending.timer.Stop()
			}
			owned = true
		}
		m.mu.Unlock()
		if owned {
			close(pending.done)
			closeUDPHalf(half)
		}
		return nil, ctx.Err()
	}
}

func closeUDPHalf(half UDPHalf) {
	if half.Uplink != nil {
		_ = half.Uplink.Close()
	}
	if half.Downlink != nil {
		_ = half.Downlink.Close()
	}
}

// --- TCP UoT halves ---

type tcpUDPUplink struct {
	conn net.Conn
	mu   sync.Mutex
}

func NewTCPUDPUplink(conn net.Conn) UDPUplink { return &tcpUDPUplink{conn: conn} }

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

func NewTCPUDPDownlink(conn net.Conn) UDPDownlink { return &tcpUDPDownlink{conn: conn} }

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

// QuicUDPUplink buffers DATAGRAM payloads for an asymmetric UDP OPEN half.
type QuicUDPUplink struct {
	ch     chan []byte
	closed chan struct{}
	once   sync.Once
}

func NewQUICUDPUplink() *QuicUDPUplink {
	return &QuicUDPUplink{
		ch:     make(chan []byte, 64),
		closed: make(chan struct{}),
	}
}

func (u *QuicUDPUplink) Deliver(p []byte) {
	select {
	case <-u.closed:
		return
	default:
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case u.ch <- cp:
	default:
		select {
		case <-u.ch:
		default:
		}
		select {
		case u.ch <- cp:
		default:
		}
	}
}

func (u *QuicUDPUplink) ReadPacket() ([]byte, error) {
	select {
	case p, ok := <-u.ch:
		if !ok {
			return nil, io.EOF
		}
		return p, nil
	case <-u.closed:
		return nil, io.EOF
	}
}

func (u *QuicUDPUplink) Close() error {
	u.once.Do(func() { close(u.closed) })
	return nil
}

type quicUDPDownlink struct {
	send func([]byte) error
}

func NewQUICUDPDownlink(send func([]byte) error) UDPDownlink {
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

func NewQUICCompactAck(send func([]byte) error, mark func()) CompactAck {
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

// pairedUDPConn exposes a PairedUDP as net.PacketConn.
type pairedUDPConn struct {
	flowID     uint64
	dest       net.Addr
	uplink     UDPUplink
	downlink   UDPDownlink
	compactAck CompactAck
	ackOnce    sync.Once
	closeOnce  sync.Once
}

// NewPairedUDPConn adapts a PairedUDP to net.PacketConn.
func NewPairedUDPConn(paired *PairedUDP) net.PacketConn {
	down := paired.Downlink
	if q, ok := down.(*quicUDPDownlink); ok {
		down = &quicUDPDownlinkBound{flowID: paired.FlowID, send: q.send}
	}
	dest := parseTargetAddr(paired.Target)
	return &pairedUDPConn{
		flowID:     paired.FlowID,
		dest:       dest,
		uplink:     paired.Uplink,
		downlink:   down,
		compactAck: paired.CompactAck,
	}
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
	for {
		payload, err := c.uplink.ReadPacket()
		if err != nil {
			return 0, nil, err
		}
		if len(payload) == 0 {
			continue
		}
		c.sendAck()
		n = copy(p, payload)
		return n, c.dest, nil
	}
}

func (c *pairedUDPConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	if err := c.downlink.WritePacket(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *pairedUDPConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.downlink.WriteClose(c.flowID)
		_ = c.uplink.Close()
		_ = c.downlink.Close()
	})
	return nil
}

func (c *pairedUDPConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *pairedUDPConn) SetDeadline(time.Time) error      { return nil }
func (c *pairedUDPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pairedUDPConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.PacketConn = (*pairedUDPConn)(nil)
