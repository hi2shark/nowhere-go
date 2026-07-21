package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

const (
	// DefaultFlowSetupTimeout bounds waiting for Portal READY/REJECT after FLOW
	// is sent. It is independent of the 5s auth/handshake timeout.
	DefaultFlowSetupTimeout = 20 * time.Second
)

// ErrFlowSetupTimeout reports that Portal did not return READY/REJECT within
// DefaultFlowSetupTimeout (or a caller-supplied override).
var ErrFlowSetupTimeout = errors.New("nowhere: flow setup timed out waiting for READY")

// flowSetup holds the metadata for a prepared flow half. In 1.5 the wire bytes
// are assembled from the header and an optional typed target; there is no
// protocol specification object to thread through.
type flowSetup struct {
	header wire.FlowHeader
	target wire.Target
}

// bytes encodes the flow header and, when the role carries a target, the
// SOCKS5 target bytes.
func (s flowSetup) bytes() ([]byte, error) {
	return encodeFlowSetupBytes(s.header, s.target)
}

func encodeFlowSetupBytes(header wire.FlowHeader, target wire.Target) ([]byte, error) {
	hdr, err := wire.WriteFlowHeader(header)
	if err != nil {
		return nil, err
	}
	if !header.CarriesTarget() {
		out := make([]byte, wire.FlowHeaderLen)
		copy(out, hdr[:])
		return out, nil
	}
	targetBytes, err := wire.EncodeTarget(target)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, wire.FlowHeaderLen+len(targetBytes))
	out = append(out, hdr[:]...)
	out = append(out, targetBytes...)
	return out, nil
}

func (b *CarrierBundle) newFlowSetup(kind wire.FlowKind, role wire.FlowRole, target wire.Target) (flowSetup, error) {
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
		target: target,
	}, nil
}

func (b *CarrierBundle) newDuplexSetup(kind wire.FlowKind, target wire.Target) (flowSetup, error) {
	return b.newFlowSetup(kind, wire.FlowRoleDuplex, target)
}

// prepareTCPHalf acquires an authenticated TLS/TCP carrier for the given header.
func (b *CarrierBundle) prepareTCPHalf(ctx context.Context, target wire.Target, header wire.FlowHeader) (*tcptls.PreparedFlowHalf, error) {
	pool, err := b.tcpPool()
	if err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, errors.New("nowhere: tcp carrier unavailable")
	}
	return pool.PrepareFlowHalf(ctx, target, header)
}

// quicPreparedStream wraps carrier/quic.PreparedStream with session lifetime.
type quicPreparedStream struct {
	client  carrier.QuicBackend
	session carrier.QuicSession
	stream  quic.PreparedStream
	id      wire.FlowID
}

func (b *CarrierBundle) prepareQUICStream(ctx context.Context, flowID wire.FlowID) (*quicPreparedStream, error) {
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

func (p *quicPreparedStream) flowID() wire.FlowID {
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

func (p *quicPreparedStream) SendDatagram(ctx context.Context, frame []byte) error {
	if p == nil || p.session == nil {
		return errors.New("nowhere: nil quic session")
	}
	return p.session.SendDatagram(ctx, frame)
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

// readSetupResult reads the single-byte SetupResult from the selected downlink
// and returns an error if the server rejected the flow. Nowhere 1.5 collapses
// the former F2 and UoT setup-result formats into one byte.
//
// The wait is bounded by DefaultFlowSetupTimeout so a slow Portal dial cannot
// reuse the shorter auth/handshake deadline.
func readSetupResult(r io.Reader) error {
	return readSetupResultWithTimeout(r, DefaultFlowSetupTimeout)
}

func readSetupResultWithTimeout(r io.Reader, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = DefaultFlowSetupTimeout
	}
	if d, ok := r.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = d.SetReadDeadline(time.Time{}) }()
	}
	result, err := wire.ReadSetupResult(r)
	if err != nil {
		if isTimeoutErr(err) {
			return ErrFlowSetupTimeout
		}
		return err
	}
	if !result.IsReady() {
		return &SetupResultError{Code: result}
	}
	return nil
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// SetupResultError preserves the exact non-READY result code while callers add
// stage context with %w.
type SetupResultError struct {
	Code wire.SetupResult
}

func (e *SetupResultError) Error() string {
	if e == nil {
		return "nowhere: flow rejected"
	}
	return fmt.Sprintf("nowhere: flow rejected: %s", e.Code.String())
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
func (c *splicedConn) Close() error {
	var errs []error
	for _, cl := range c.closer {
		if e := cl.Close(); e != nil {
			errs = append(errs, e)
		}
	}
	return errors.Join(errs...)
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

// commitTCPFlow writes the FLOW setup on a TCP half and reads the SetupResult.
func commitTCPFlow(half *tcptls.PreparedFlowHalf) (net.Conn, error) {
	conn, err := half.Commit()
	if err != nil {
		return nil, err
	}
	if err := readSetupResult(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// commitQUICHalf writes setup bytes while preserving the caller-selected send-side state.
func commitQUICHalf(ctx context.Context, prep *quicPreparedStream, setup []byte, finishWrite bool) (net.Conn, error) {
	return prep.commit(ctx, setup, finishWrite)
}

// commitQUICFlow writes a control-only setup and reads the SetupResult.
func commitQUICFlow(ctx context.Context, prep *quicPreparedStream, setup []byte) (net.Conn, error) {
	conn, err := prep.Commit(ctx, setup)
	if err != nil {
		return nil, err
	}
	if err := readSetupResult(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func asymmetricCarrierIDs(up, down wire.Carrier, tcpIsOpen bool, tcpCarrierID uint64) (upID, downID uint64) {
	if up == wire.CarrierTLSTCP {
		upID = tcpCarrierID
	}
	if down == wire.CarrierTLSTCP {
		downID = tcpCarrierID
	}
	_ = tcpIsOpen
	return upID, downID
}

func carrierTransportName(c wire.Carrier) string {
	switch c {
	case wire.CarrierQUIC:
		return "quic"
	default:
		return "tcp"
	}
}

// closeAll closes a list of io.Closers and preserves every close failure.
func closeAll(closers ...io.Closer) error {
	var errs []error
	for _, cl := range closers {
		if cl == nil {
			continue
		}
		if err := cl.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// fmtError wraps an error with context.
func fmtError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("nowhere: %s: %w", stage, err)
}
