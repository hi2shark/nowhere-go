package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hi2shark/go-nowhere/wire"
)

func (b *CarrierBundle) AsymmetricOpenTCP(ctx context.Context, dest string) (net.Conn, error) {
	up, down := b.UpCarrier(), b.DownCarrier()
	flowID := b.allocFlowID()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type half struct {
		role string
		conn net.Conn
		err  error
	}
	closePendingHalf := func(resultCh <-chan half) {
		res := <-resultCh
		if res.conn != nil {
			_ = res.conn.Close()
		}
	}
	resultCh := make(chan half, 2)
	go func() {
		c, e := b.openTCPHalf(ctx, wire.FlowHeader{Role: wire.FlowRoleOpen, FlowID: flowID, Kind: wire.FlowKindTCP, Uplink: up, Downlink: down}, dest)
		resultCh <- half{role: "uplink", conn: c, err: e}
	}()
	go func() {
		c, e := b.openTCPHalf(ctx, wire.FlowHeader{Role: wire.FlowRoleAttach, FlowID: flowID, Kind: wire.FlowKindTCP, Uplink: up, Downlink: down}, dest)
		resultCh <- half{role: "downlink", conn: c, err: e}
	}()

	first := <-resultCh
	if first.err != nil {
		cancel()
		go closePendingHalf(resultCh)
		return nil, fmt.Errorf("nowhere: open %s half: %w", first.role, first.err)
	}
	second := <-resultCh
	if second.err != nil {
		cancel()
		_ = first.conn.Close()
		return nil, fmt.Errorf("nowhere: open %s half: %w", second.role, second.err)
	}

	var openRes, attachRes half
	if first.role == "uplink" {
		openRes, attachRes = first, second
	} else {
		openRes, attachRes = second, first
	}

	return &splicedConn{
		reader: attachRes.conn,
		writer: openRes.conn,
		closer: []io.Closer{openRes.conn, attachRes.conn},
		remote: openRes.conn.RemoteAddr(),
		local:  openRes.conn.LocalAddr(),
	}, nil
}

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
