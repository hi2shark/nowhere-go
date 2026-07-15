package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

// flowSetup holds the bytes and metadata for a prepared flow half.
type flowSetup struct {
	header wire.FlowHeader
	dest   string
}

func (s *flowSetup) bytes(spec *wire.EffectiveSpec) ([]byte, error) {
	return wire.EncodeFlowSetup(s.header, s.dest, spec)
}

func (b *CarrierBundle) newFlowSetup(kind wire.FlowKind, role wire.FlowRole, dest string) (flowSetup, error) {
	flowID, err := b.allocFlowID()
	if err != nil {
		return flowSetup{}, err
	}
	return flowSetup{
		header: wire.FlowHeader{
			Role:     role,
			FlowID:   flowID,
			Kind:     kind,
			Uplink:   b.cfg.up,
			Downlink: b.cfg.down,
		},
		dest: dest,
	}, nil
}

func (b *CarrierBundle) newDuplexSetup(kind wire.FlowKind, dest string) (flowSetup, error) {
	return b.newFlowSetup(kind, wire.FlowRoleDuplex, dest)
}

// prepareTCPHalf acquires an authenticated TLS/TCP carrier for the given header.
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

// quicPreparedStream wraps carrier/quic.PreparedStream with session lifetime.
type quicPreparedStream struct {
	client  carrier.QuicBackend
	session carrier.QuicSession
	stream  quic.PreparedStream
	id      uint64
}

func (b *CarrierBundle) prepareQUICStream(ctx context.Context, flowID uint64) (*quicPreparedStream, error) {
	client, err := b.quicClient()
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("nowhere: udp carrier unavailable")
	}
	for retries := 1; retries >= 0; retries-- {
		session, err := client.AcquireSession(ctx)
		if err != nil {
			return nil, err
		}
		stream, err := session.PrepareStream(ctx)
		if err != nil {
			if retries > 0 {
				client.InvalidateSession(session)
				continue
			}
			return nil, err
		}
		return &quicPreparedStream{client: client, session: session, stream: stream, id: flowID}, nil
	}
	return nil, errors.New("nowhere: quic stream unavailable")
}

func (p *quicPreparedStream) flowID() uint64 {
	if p == nil {
		return 0
	}
	return p.id
}

func (p *quicPreparedStream) commit(ctx context.Context, setup []byte, finishWrite bool) (net.Conn, error) {
	if p == nil || p.stream == nil {
		return nil, errors.New("nowhere: nil prepared stream")
	}
	return p.stream.Commit(ctx, setup, finishWrite)
}

func (p *quicPreparedStream) Commit(ctx context.Context, setup []byte) (net.Conn, error) {
	return p.commit(ctx, setup, true)
}

func (p *quicPreparedStream) Close() error {
	if p == nil || p.stream == nil {
		return nil
	}
	return p.stream.Close()
}

func (p *quicPreparedStream) SendDatagram(frame []byte) error {
	if p == nil || p.session == nil {
		return errors.New("nowhere: nil quic session")
	}
	return p.session.SendDatagram(frame)
}

func (p *quicPreparedStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if p == nil || p.session == nil {
		return nil, errors.New("nowhere: nil quic session")
	}
	return p.session.ReceiveDatagram(ctx)
}

func (p *quicPreparedStream) MaxDatagramSize() int {
	if p == nil || p.session == nil {
		return 1200
	}
	return p.session.CurrentMaxDatagramSize()
}

func (p *quicPreparedStream) LocalAddr() net.Addr {
	if p == nil || p.session == nil {
		return &net.UDPAddr{}
	}
	return p.session.LocalAddr()
}

// readFlowResult reads and validates a FLOW_RESULT frame from the selected downlink.
func readFlowResult(r io.Reader) error {
	result, err := wire.ReadFlowResult(r)
	if err != nil {
		return err
	}
	return result.Err(true)
}

// splicedConn joins an independent reader and writer into net.Conn.
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

// commitTCPFlow writes the FLOW setup on a TCP half and reads FLOW_RESULT.
func commitTCPFlow(half *tcptls.PreparedFlowHalf) (net.Conn, error) {
	conn, err := half.Commit()
	if err != nil {
		return nil, err
	}
	if err := readFlowResult(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// commitQUICHalf writes setup bytes while preserving the caller-selected send-side state.
func commitQUICHalf(ctx context.Context, prep *quicPreparedStream, setup []byte, finishWrite bool) (net.Conn, error) {
	return prep.commit(ctx, setup, finishWrite)
}

// commitQUICFlow writes a control-only setup and reads FLOW_RESULT.
func commitQUICFlow(ctx context.Context, prep *quicPreparedStream, setup []byte) (net.Conn, error) {
	conn, err := prep.Commit(ctx, setup)
	if err != nil {
		return nil, err
	}
	if err := readFlowResult(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func asymmetricCarrierIDs(up, down wire.Carrier, tcpIsOpen bool, tcpCarrierID uint64) (upID, downID uint64) {
	if up == wire.CarrierTCP {
		upID = tcpCarrierID
	}
	if down == wire.CarrierTCP {
		downID = tcpCarrierID
	}
	_ = tcpIsOpen
	return upID, downID
}

func carrierTransportName(c wire.Carrier) string {
	switch c {
	case wire.CarrierUDP:
		return "quic"
	default:
		return "tcp"
	}
}

// closeAll closes a list of io.Closers, returning the first error.
func closeAll(closers ...io.Closer) error {
	var first error
	for _, cl := range closers {
		if cl == nil {
			continue
		}
		if err := cl.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// fmtError wraps an error with context.
func fmtError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("nowhere: %s: %w", stage, err)
}
