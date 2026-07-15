package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/diagnostic"
	"github.com/hi2shark/nowhere-go/wire"
)

// flowPairManager is retained as an internal compatibility name for the unified registry.
type flowPairManager = claimRegistry

func newFlowPairManager(timeout time.Duration) *flowPairManager {
	limits, _ := normalizeLimits(Limits{})
	return newClaimRegistry(timeout, limits)
}

func (r *claimRegistry) configureLimits(limits Limits) {
	normalized, err := normalizeLimits(limits)
	if err != nil {
		return
	}
	r.mu.Lock()
	r.limits = normalized
	r.mu.Unlock()
}

func (r *claimRegistry) setObserver(observer diagnostic.Observer) {
	r.mu.Lock()
	r.observer = observer
	r.mu.Unlock()
}

func (r *claimRegistry) RejectFlowSetup(sessionID wire.SessionID, flowID uint64, code wire.FlowErrorCode) {
	r.Reject(sessionID, flowID, r.CurrentGeneration(sessionID), &wire.FlowError{Code: code})
}

// SubmitTCP caches or pairs a TCP half.
func (r *claimRegistry) SubmitTCP(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target string, conn net.Conn) (net.Conn, error) {
	return r.SubmitTCPWithSource(ctx, sessionID, header, target, conn, nil)
}

// SubmitTCPWithSource is SubmitTCP with optional source for diagnostics.
func (r *claimRegistry) SubmitTCPWithSource(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target string, conn net.Conn, source net.Addr) (net.Conn, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: nil tcp half", ErrInvalidHandler)
	}
	if err := validatePairHeader(header, wire.FlowKindTCP); err != nil {
		return nil, err
	}
	carrier := header.Uplink
	if header.Role == wire.FlowRoleAttach {
		carrier = header.Downlink
		target = ""
	}
	active, err := r.Submit(ctx, flowClaim{
		SessionID: sessionID, FlowID: header.FlowID, Generation: r.CurrentGeneration(sessionID),
		Role: header.Role, Carrier: carrier,
		Metadata: claimMetadata{Kind: header.Kind, Uplink: header.Uplink, Downlink: header.Downlink},
		Target:   target, Stream: conn, Source: source,
	})
	if err != nil || active == nil {
		return nil, err
	}
	if active.Open == nil || active.Attach == nil {
		active.Release()
		return nil, fmt.Errorf("%w: incomplete TCP pair", ErrInvalidHandler)
	}
	return &splicedConn{
		reader: active.Open.Stream, writer: active.Attach.Stream,
		closer: []io.Closer{active.Open.Stream, active.Attach.Stream},
		remote: active.Open.Stream.RemoteAddr(), local: active.Open.Stream.LocalAddr(),
		target: active.Target, resultWriter: active.Selected.Stream,
		onClose: active.Release,
	}, nil
}

func validatePairHeader(header wire.FlowHeader, kind wire.FlowKind) error {
	if header.Kind != kind || header.FlowID == 0 {
		return fmt.Errorf("%w: invalid flow header", ErrUnsupportedFlow)
	}
	if header.Role != wire.FlowRoleOpen && header.Role != wire.FlowRoleAttach {
		return fmt.Errorf("%w: invalid role", ErrUnsupportedFlow)
	}
	if header.Uplink == header.Downlink ||
		(header.Uplink != wire.CarrierTCP && header.Uplink != wire.CarrierUDP) ||
		(header.Downlink != wire.CarrierTCP && header.Downlink != wire.CarrierUDP) {
		return fmt.Errorf("%w: invalid carriers", ErrCarrierMismatch)
	}
	return nil
}

func carrierTransportName(c wire.Carrier) string {
	if c == wire.CarrierUDP {
		return "quic"
	}
	return "tcp"
}

func flowRoleName(role wire.FlowRole) string {
	switch role {
	case wire.FlowRoleOpen:
		return "open"
	case wire.FlowRoleAttach:
		return "attach"
	case wire.FlowRoleDuplex:
		return "duplex"
	default:
		return "unknown"
	}
}

type splicedConn struct {
	reader       io.Reader
	writer       io.Writer
	closer       []io.Closer
	remote       net.Addr
	local        net.Addr
	target       string
	resultWriter net.Conn
	onClose      func()
	once         sync.Once
}

func (c *splicedConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *splicedConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *splicedConn) Close() (err error) {
	c.once.Do(func() {
		for _, closer := range c.closer {
			if closeErr := closer.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

func (c *splicedConn) closeWithError(cause error) {
	c.once.Do(func() {
		for _, closer := range c.closer {
			if conn, ok := closer.(net.Conn); ok {
				closeConnWithError(conn, cause)
			} else {
				_ = closer.Close()
			}
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
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
	if deadline, ok := c.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		return deadline.SetReadDeadline(t)
	}
	return nil
}
func (c *splicedConn) SetWriteDeadline(t time.Time) error {
	if deadline, ok := c.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return deadline.SetWriteDeadline(t)
	}
	return nil
}

var _ net.Conn = (*splicedConn)(nil)
