package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

// udpHalf is one side of an asymmetric UDP flow.
type udpHalf struct {
	Role         wire.FlowRole
	Uplink       udpUplink
	Downlink     udpDownlink
	compactLease *compactGenerationLease
}

type udpUplink interface {
	ReadPacket() ([]byte, error)
	SetReadDeadline(time.Time) error
	Close() error
}

type udpDownlink interface {
	WritePacket([]byte) error
	WriteAck(uint64) error
	WriteClose(uint64) error
	Close() error
}

func udpHalfTransport(header wire.FlowHeader, half udpHalf) string {
	carrier := header.Uplink
	if half.Role == wire.FlowRoleAttach {
		carrier = header.Downlink
	}
	switch carrier {
	case wire.CarrierUDP:
		if half.Role == wire.FlowRoleAttach {
			return "quic"
		}
		return "udp"
	default:
		return "tcp"
	}
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

func (u *tcpUDPUplink) SetReadDeadline(value time.Time) error {
	return u.conn.SetReadDeadline(value)
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
	readDL  deadlineState
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
	for {
		wait, expired := u.readDL.newReadWait(time.Now())
		if expired {
			return nil, deadlineError()
		}
		select {
		case p := <-u.ch:
			wait.stop()
			if u.session != nil {
				u.session.releaseQueueBytes(len(p))
			}
			return p, nil
		case <-u.closed:
			wait.stop()
			return nil, io.EOF
		case <-wait.changed:
			wait.stop()
		case <-wait.timerC:
			if wait.timerExpired(time.Now()) {
				return nil, deadlineError()
			}
		}
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

func (d *quicUDPDownlink) WritePacket([]byte) error {
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
	lease  *compactGenerationLease
}

func (d *quicUDPDownlinkBound) WritePacket(p []byte) error {
	if d.lease != nil {
		return d.lease.SendData(p)
	}
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeData, d.flowID, p)
	if err != nil {
		return err
	}
	return d.send(frame)
}

func (d *quicUDPDownlinkBound) WriteAck(flowID uint64) error {
	if d.lease != nil {
		return d.lease.SendOpenAck()
	}
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeOpenAck, flowID, nil)
	if err != nil {
		return err
	}
	return d.send(frame)
}

func (d *quicUDPDownlinkBound) WriteClose(flowID uint64) error {
	if d.lease != nil {
		return d.lease.SendTerminalClose()
	}
	frame, err := wire.EncodeUDPCompact(wire.UDPTypeCompactClose, flowID, nil)
	if err != nil {
		return err
	}
	return d.send(frame)
}

func (d *quicUDPDownlinkBound) Close() error { return nil }
