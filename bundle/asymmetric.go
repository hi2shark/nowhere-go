package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

func (b *CarrierBundle) AsymmetricOpenTCP(ctx context.Context, dest string) (net.Conn, error) {
	up, down := b.UpCarrier(), b.DownCarrier()
	flowID := b.allocFlowID()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	openHeader := wire.FlowHeader{Role: wire.FlowRoleOpen, FlowID: flowID, Kind: wire.FlowKindTCP, Uplink: up, Downlink: down}
	attachHeader := wire.FlowHeader{Role: wire.FlowRoleAttach, FlowID: flowID, Kind: wire.FlowKindTCP, Uplink: up, Downlink: down}

	var (
		tcpHeader  wire.FlowHeader
		quicHeader wire.FlowHeader
		tcpIsOpen  bool
	)
	switch {
	case up == wire.CarrierTCP && down == wire.CarrierUDP:
		tcpHeader, quicHeader, tcpIsOpen = openHeader, attachHeader, true
	case up == wire.CarrierUDP && down == wire.CarrierTCP:
		tcpHeader, quicHeader, tcpIsOpen = attachHeader, openHeader, false
	default:
		return nil, errors.New("nowhere: asymmetric tcp requires mixed carriers")
	}

	tcpHalf, err := b.prepareTCPHalf(ctx, dest, tcpHeader)
	if err != nil {
		return nil, fmt.Errorf("nowhere: prepare tcp half: %w", err)
	}
	defer func() {
		if tcpHalf != nil {
			_ = tcpHalf.Close()
		}
	}()

	quicPrep, err := b.prepareQUICHalf(ctx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("nowhere: prepare quic half: %w", err)
	}
	defer func() {
		if quicPrep != nil {
			_ = quicPrep.Close()
		}
	}()

	tcpConn, err := tcpHalf.Commit()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("nowhere: commit tcp half: %w", err)
	}
	tcpHalf = nil

	quicConn, err := quicPrep.Commit(ctx, dest, quicHeader)
	if err != nil {
		cancel()
		_ = tcpConn.Close()
		return nil, fmt.Errorf("nowhere: commit quic half: %w", err)
	}
	quicPrep = nil

	var openConn, attachConn net.Conn
	if tcpIsOpen {
		openConn, attachConn = tcpConn, quicConn
	} else {
		openConn, attachConn = quicConn, tcpConn
	}
	return &splicedConn{
		reader: attachConn,
		writer: openConn,
		closer: []io.Closer{openConn, attachConn},
		remote: openConn.RemoteAddr(),
		local:  openConn.LocalAddr(),
	}, nil
}

func (b *CarrierBundle) prepareTCPHalf(ctx context.Context, dest string, header wire.FlowHeader) (*tcptls.PreparedFlowHalf, error) {
	pool, err := b.tcpPool()
	if err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, errors.New("nowhere: tcp carrier unavailable")
	}
	return pool.PrepareFlowHalf(ctx, dest, header)
}

func (b *CarrierBundle) prepareQUICHalf(ctx context.Context) (quic.PreparedFlowStream, error) {
	client, err := b.quicClient()
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("nowhere: udp carrier unavailable")
	}
	return client.PrepareFlowStream(ctx)
}

// openTCPHalf remains for tests that exercise a single half path.
func (b *CarrierBundle) openTCPHalf(ctx context.Context, header wire.FlowHeader, dest string) (net.Conn, error) {
	carrier := header.Uplink
	if header.Role == wire.FlowRoleAttach {
		carrier = header.Downlink
	}
	switch carrier {
	case wire.CarrierUDP:
		client, err := b.quicClient()
		if err != nil {
			return nil, err
		}
		if client == nil {
			return nil, errors.New("nowhere: udp carrier unavailable")
		}
		return client.OpenFlowStream(ctx, dest, header)
	case wire.CarrierTCP:
		pool, err := b.tcpPool()
		if err != nil {
			return nil, err
		}
		if pool == nil {
			return nil, errors.New("nowhere: tcp carrier unavailable")
		}
		return pool.AcquireFlowHalf(ctx, dest, header)
	}
	return nil, errors.New("nowhere: unknown carrier")
}

type splicedConn struct {
	reader io.Reader
	writer io.Writer
	closer []io.Closer
	remote net.Addr
	local  net.Addr
}

func (c *splicedConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *splicedConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *splicedConn) Close() (err error) {
	for _, cl := range c.closer {
		if e := cl.Close(); e != nil {
			err = e
		}
	}
	return
}
func (c *splicedConn) LocalAddr() net.Addr  { return c.local }
func (c *splicedConn) RemoteAddr() net.Addr { return c.remote }
func (c *splicedConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
func (c *splicedConn) SetReadDeadline(t time.Time) error {
	if d, ok := c.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}
func (c *splicedConn) SetWriteDeadline(t time.Time) error {
	if d, ok := c.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return nil
}

var _ net.Conn = (*splicedConn)(nil)
