package bundle

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/wire"
)

var (
	_ net.PacketConn = (*asymmetricPacketConn)(nil)
	_ udpUplink      = (*quicUDPUplink)(nil)
	_ udpUplink      = (*uotLaneUplink)(nil)
	_ udpDownlink    = (*quicUDPDownlink)(nil)
	_ udpDownlink    = (*uotLaneDownlink)(nil)
)

type udpUplink interface {
	WritePacket(p []byte) (int, error)
	ClosePacket() error
}

type udpDownlink interface {
	ReadPacket(p []byte) (int, error)
	ClosePacket() error
}

type asymmetricPacketConn struct {
	dest     string
	uplink   udpUplink
	downlink udpDownlink
	upCloser io.Closer
	dnCloser io.Closer
	quicSess carrier.QuicSession
	quicFlow carrier.QuicUDPFlow
}

func (a *asymmetricPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := a.downlink.ReadPacket(p)
	if err != nil {
		return n, nil, err
	}
	return n, a.remoteAddr(), nil
}

func (a *asymmetricPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return a.uplink.WritePacket(p)
}

func (a *asymmetricPacketConn) Close() error {
	_ = a.uplink.ClosePacket()
	if a.upCloser != nil {
		_ = a.upCloser.Close()
	}
	_ = a.downlink.ClosePacket()
	if a.dnCloser != nil {
		_ = a.dnCloser.Close()
	}
	if a.quicSess != nil && a.quicFlow != nil {
		a.quicSess.ReleaseUDPAsymmetricFlow(a.quicFlow.FlowID())
	}
	return nil
}

func (a *asymmetricPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

// remoteAddr returns the flow target; empty UDPAddr is rejected by some hosts.
func (a *asymmetricPacketConn) remoteAddr() net.Addr {
	if a.dest == "" {
		return &net.UDPAddr{}
	}
	host, portStr, err := net.SplitHostPort(a.dest)
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
func (a *asymmetricPacketConn) SetDeadline(t time.Time) error {
	if err := a.SetReadDeadline(t); err != nil {
		return err
	}
	return a.SetWriteDeadline(t)
}
func (a *asymmetricPacketConn) SetReadDeadline(t time.Time) error {
	if d, ok := a.downlink.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}
func (a *asymmetricPacketConn) SetWriteDeadline(t time.Time) error {
	if d, ok := a.uplink.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return nil
}

type quicUDPUplink struct {
	client  carrier.QuicBackend
	session carrier.QuicSession
	flow    carrier.QuicUDPFlow
	target  string
	down    wire.Carrier
}

func (u *quicUDPUplink) WritePacket(p []byte) (int, error) {
	var frame []byte
	var err error
	if u.flow.IsAcked() {
		frame, err = wire.EncodeUDPCompact(wire.UDPTypeData, u.flow.FlowID(), p)
	} else {
		frame, err = wire.EncodeUDPOpenData(u.flow.FlowID(), u.down, u.target, p)
	}
	if err != nil {
		return 0, err
	}
	if err := u.session.SendDatagram(frame); err != nil {
		u.client.InvalidateSession(u.session)
		return 0, err
	}
	return len(p), nil
}

func (u *quicUDPUplink) ClosePacket() error {
	closeFrame, _ := wire.EncodeUDPCompact(wire.UDPTypeCompactClose, u.flow.FlowID(), nil)
	_ = u.session.SendDatagram(closeFrame)
	u.session.ReleaseUDPAsymmetricFlow(u.flow.FlowID())
	return nil
}

type quicUDPDownlink struct {
	flow carrier.QuicUDPFlow
}

func (d *quicUDPDownlink) ReadPacket(p []byte) (int, error) {
	data, put, _, err := d.flow.WaitReadFrom()
	if err != nil {
		return 0, err
	}
	n := copy(p, data)
	if put != nil {
		put()
	}
	return n, nil
}

func (d *quicUDPDownlink) ClosePacket() error {
	d.flow.Shutdown(io.EOF)
	return nil
}

type uotLaneUplink struct {
	raw net.Conn
}

func (u *uotLaneUplink) WritePacket(p []byte) (int, error) {
	frame, err := wire.WriteUOTPacketFrame(p)
	if err != nil {
		return 0, err
	}
	if _, err := u.raw.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (u *uotLaneUplink) ClosePacket() error { return u.raw.Close() }

func (u *uotLaneUplink) SetWriteDeadline(t time.Time) error {
	return u.raw.SetWriteDeadline(t)
}

type uotLaneDownlink struct {
	raw net.Conn
}

func (d *uotLaneDownlink) ReadPacket(p []byte) (int, error) {
	for {
		var lenBuf [2]byte
		if _, err := io.ReadFull(d.raw, lenBuf[:]); err != nil {
			return 0, err
		}
		length := int(binary.BigEndian.Uint16(lenBuf[:]))
		if length == 0 {
			continue // empty UoT = OPEN_ACK / CLOSE
		}
		if length > len(p) {
			if _, err := io.CopyN(io.Discard, d.raw, int64(length)); err != nil {
				return 0, err
			}
			return 0, fmt.Errorf("nowhere: uot packet %d exceeds buffer %d", length, len(p))
		}
		if _, err := io.ReadFull(d.raw, p[:length]); err != nil {
			return 0, err
		}
		return length, nil
	}
}

func (d *uotLaneDownlink) ClosePacket() error { return d.raw.Close() }

func (d *uotLaneDownlink) SetReadDeadline(t time.Time) error {
	return d.raw.SetReadDeadline(t)
}
