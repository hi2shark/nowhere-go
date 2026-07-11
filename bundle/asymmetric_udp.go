package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

func (b *CarrierBundle) AsymmetricOpenUDP(ctx context.Context, dest string) (net.PacketConn, error) {
	up, down := b.UpCarrier(), b.DownCarrier()
	flowID := b.allocFlowID()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var quicFlow carrier.QuicUDPFlow
	var quicSession carrier.QuicSession
	if up == wire.CarrierUDP || down == wire.CarrierUDP {
		client, err := b.quicClient()
		if err != nil {
			return nil, err
		}
		if client == nil {
			return nil, errors.New("nowhere: udp carrier unavailable")
		}
		s, err := client.AcquireSession(ctx)
		if err != nil {
			return nil, err
		}
		if err := s.EnsureReady(ctx); err != nil {
			return nil, err
		}
		quicFlow, err = s.RegisterUDPAsymmetricFlow(ctx, dest, flowID)
		if err != nil {
			return nil, err
		}
		quicSession = s
	}

	switch {
	case up == wire.CarrierTCP && down == wire.CarrierUDP:
		return b.openTCPUDP(ctx, cancel, dest, flowID, up, down, quicSession, quicFlow)
	case up == wire.CarrierUDP && down == wire.CarrierTCP:
		return b.openUDPTCP(ctx, cancel, dest, flowID, up, down, quicSession, quicFlow)
	default:
		b.releaseQUICFlow(quicSession, quicFlow)
		return nil, errors.New("nowhere: asymmetric udp requires mixed carriers")
	}
}

// openTCPUDP: prepare TCP OPEN + QUIC ATTACH, then commit both before returning.
func (b *CarrierBundle) openTCPUDP(
	ctx context.Context,
	cancel context.CancelFunc,
	dest string,
	flowID uint64,
	up, down wire.Carrier,
	quicSession carrier.QuicSession,
	quicFlow carrier.QuicUDPFlow,
) (net.PacketConn, error) {
	started := time.Now()
	pool, err := b.tcpPool()
	if err != nil {
		b.releaseQUICFlow(quicSession, quicFlow)
		return nil, err
	}
	if pool == nil {
		b.releaseQUICFlow(quicSession, quicFlow)
		return nil, errors.New("nowhere: tcp uplink carrier unavailable")
	}
	openHeader := wire.FlowHeader{Role: wire.FlowRoleOpen, FlowID: flowID, Kind: wire.FlowKindUDP, Uplink: up, Downlink: down}
	tcpHalf, err := pool.PrepareUDPFlowHalf(ctx, dest, openHeader)
	if err != nil {
		b.releaseQUICFlow(quicSession, quicFlow)
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, dest, up, down, 0, 0, started, err)
		return nil, err
	}
	tcpCarrierID := tcpHalf.CarrierID()
	defer func() {
		if tcpHalf != nil {
			_ = tcpHalf.Close()
		}
	}()

	client := b.quicClientSync()
	if client == nil {
		b.releaseQUICFlow(quicSession, quicFlow)
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, dest, up, down, tcpCarrierID, 0, started, errors.New("nowhere: udp downlink carrier unavailable"))
		return nil, errors.New("nowhere: udp downlink carrier unavailable")
	}
	quicPrep, err := client.PrepareFlowStream(ctx)
	if err != nil {
		cancel()
		b.releaseQUICFlow(quicSession, quicFlow)
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, dest, up, down, tcpCarrierID, 0, started, err)
		return nil, err
	}
	defer func() {
		if quicPrep != nil {
			_ = quicPrep.Close()
		}
	}()

	tcpConn, err := tcpHalf.Commit()
	if err != nil {
		cancel()
		b.releaseQUICFlow(quicSession, quicFlow)
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, dest, up, down, tcpCarrierID, 0, started, err)
		return nil, fmt.Errorf("nowhere: commit tcp open half: %w", err)
	}
	tcpHalf = nil

	attachHeader := wire.FlowHeader{Role: wire.FlowRoleAttach, FlowID: flowID, Kind: wire.FlowKindUDP, Uplink: up, Downlink: down}
	attach, err := quicPrep.Commit(ctx, dest, attachHeader)
	if err != nil {
		cancel()
		_ = tcpConn.Close()
		b.releaseQUICFlow(quicSession, quicFlow)
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, dest, up, down, tcpCarrierID, 0, started, err)
		return nil, fmt.Errorf("nowhere: commit quic attach half: %w", err)
	}
	quicPrep = nil

	b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, dest, up, down, tcpCarrierID, 0, started, nil)
	return &asymmetricPacketConn{
		dest:     dest,
		uplink:   &uotLaneUplink{raw: tcpConn},
		downlink: &quicUDPDownlink{flow: quicFlow},
		upCloser: tcpConn,
		dnCloser: attach,
		quicSess: quicSession,
		quicFlow: quicFlow,
	}, nil
}

// openUDPTCP: prepare TCP ATTACH first; commit it on the first OPEN_DATA write.
func (b *CarrierBundle) openUDPTCP(
	ctx context.Context,
	cancel context.CancelFunc,
	dest string,
	flowID uint64,
	up, down wire.Carrier,
	quicSession carrier.QuicSession,
	quicFlow carrier.QuicUDPFlow,
) (net.PacketConn, error) {
	_ = ctx
	pool, err := b.tcpPool()
	if err != nil {
		b.releaseQUICFlow(quicSession, quicFlow)
		return nil, err
	}
	if pool == nil {
		b.releaseQUICFlow(quicSession, quicFlow)
		return nil, errors.New("nowhere: tcp downlink carrier unavailable")
	}
	attachHeader := wire.FlowHeader{Role: wire.FlowRoleAttach, FlowID: flowID, Kind: wire.FlowKindUDP, Uplink: up, Downlink: down}
	tcpHalf, err := pool.PrepareUDPFlowHalf(ctx, dest, attachHeader)
	if err != nil {
		b.releaseQUICFlow(quicSession, quicFlow)
		return nil, err
	}

	pending := &pendingAttachConn{}
	uplink := &deferredAttachUplink{
		inner: &quicUDPUplink{
			client:  b.quicClientSync(),
			session: quicSession,
			flow:    quicFlow,
			target:  dest,
			down:    down,
		},
		prepared: tcpHalf,
		cancel:   cancel,
		pending:  pending,
	}
	pending.uplink = uplink

	return &asymmetricPacketConn{
		dest:     dest,
		uplink:   uplink,
		downlink: &uotLaneDownlink{raw: pending},
		quicSess: quicSession,
		quicFlow: quicFlow,
	}, nil
}

// deferredAttachUplink commits the prepared TCP ATTACH immediately before the
// first OPEN_DATA datagram so both halves reach the portal together.
type deferredAttachUplink struct {
	inner    *quicUDPUplink
	prepared *tcptls.PreparedFlowHalf
	cancel   context.CancelFunc
	pending  *pendingAttachConn

	once      sync.Once
	commitErr error
	conn      net.Conn
}

func (u *deferredAttachUplink) ensureCommitted() error {
	u.once.Do(func() {
		if u.prepared == nil {
			u.commitErr = errors.New("nowhere: tcp attach already released")
			return
		}
		conn, err := u.prepared.Commit()
		u.prepared = nil
		if err != nil {
			u.commitErr = fmt.Errorf("nowhere: commit tcp attach half: %w", err)
			if u.cancel != nil {
				u.cancel()
			}
			return
		}
		u.conn = conn
		if u.pending != nil {
			u.pending.conn = conn
		}
	})
	return u.commitErr
}

func (u *deferredAttachUplink) WritePacket(p []byte) (int, error) {
	if err := u.ensureCommitted(); err != nil {
		return 0, err
	}
	return u.inner.WritePacket(p)
}

func (u *deferredAttachUplink) ClosePacket() error {
	var closeErr error
	u.once.Do(func() {
		if u.prepared != nil {
			closeErr = u.prepared.Close()
			u.prepared = nil
		}
	})
	if u.conn != nil {
		if err := u.conn.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	if u.inner != nil {
		if err := u.inner.ClosePacket(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func (u *deferredAttachUplink) SetWriteDeadline(t time.Time) error {
	if err := u.ensureCommitted(); err != nil {
		return err
	}
	if u.conn == nil {
		return nil
	}
	return u.conn.SetWriteDeadline(t)
}

// pendingAttachConn stands in as the TCP downlink until ATTACH is committed.
type pendingAttachConn struct {
	uplink *deferredAttachUplink
	conn   net.Conn
}

func (c *pendingAttachConn) Read(p []byte) (int, error) {
	if err := c.uplink.ensureCommitted(); err != nil {
		return 0, err
	}
	if c.conn == nil {
		return 0, net.ErrClosed
	}
	return c.conn.Read(p)
}

func (c *pendingAttachConn) Write(p []byte) (int, error) {
	if err := c.uplink.ensureCommitted(); err != nil {
		return 0, err
	}
	if c.conn == nil {
		return 0, net.ErrClosed
	}
	return c.conn.Write(p)
}

func (c *pendingAttachConn) Close() error {
	if c.uplink != nil {
		return c.uplink.ClosePacket()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *pendingAttachConn) LocalAddr() net.Addr {
	if c.conn != nil {
		return c.conn.LocalAddr()
	}
	return &net.TCPAddr{}
}

func (c *pendingAttachConn) RemoteAddr() net.Addr {
	if c.conn != nil {
		return c.conn.RemoteAddr()
	}
	return &net.TCPAddr{}
}

func (c *pendingAttachConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *pendingAttachConn) SetReadDeadline(t time.Time) error {
	if err := c.uplink.ensureCommitted(); err != nil {
		return err
	}
	if c.conn == nil {
		return nil
	}
	return c.conn.SetReadDeadline(t)
}

func (c *pendingAttachConn) SetWriteDeadline(t time.Time) error {
	if err := c.uplink.ensureCommitted(); err != nil {
		return err
	}
	if c.conn == nil {
		return nil
	}
	return c.conn.SetWriteDeadline(t)
}

var (
	_ net.Conn   = (*pendingAttachConn)(nil)
	_ udpUplink  = (*deferredAttachUplink)(nil)
	_ io.Closer  = (*pendingAttachConn)(nil)
)
