package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hi2shark/go-nowhere/wire"
)

type flowKey struct {
	session wire.SessionID
	flowID  uint64
	kind    wire.FlowKind
	target  string
	up      wire.Carrier
	down    wire.Carrier
}

type pendingHalf struct {
	role      wire.FlowRole
	conn      net.Conn
	timer     *time.Timer
	done      chan struct{}
	completed bool // peer paired successfully
	timedOut  bool
}

// FlowPairManager pairs asymmetric FLOW_OPEN / FLOW_ATTACH halves.
type FlowPairManager struct {
	timeout    time.Duration
	mu         sync.Mutex
	pending    map[flowKey]*pendingHalf
	pendingUDP map[flowKey]*pendingUDPHalf
}

func NewFlowPairManager(timeout time.Duration) *FlowPairManager {
	if timeout <= 0 {
		timeout = DefaultFlowPairTimeout
	}
	return &FlowPairManager{
		timeout:    timeout,
		pending:    make(map[flowKey]*pendingHalf),
		pendingUDP: make(map[flowKey]*pendingUDPHalf),
	}
}

func (m *FlowPairManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, half := range m.pending {
		if half.timer != nil {
			half.timer.Stop()
		}
		_ = half.conn.Close()
		select {
		case <-half.done:
		default:
			close(half.done)
		}
		delete(m.pending, key)
	}
	for key, half := range m.pendingUDP {
		if half.timer != nil {
			half.timer.Stop()
		}
		closeUDPHalf(UDPHalf{Role: half.role, Uplink: half.uplink, Downlink: half.downlink})
		select {
		case <-half.done:
		default:
			close(half.done)
		}
		delete(m.pendingUDP, key)
	}
}

// SubmitTCP caches or pairs a TCP half.
// Completing half returns the spliced connection; waiting half returns (nil, nil) after peer completes,
// or an error on timeout/cancel.
func (m *FlowPairManager) SubmitTCP(ctx context.Context, sessionID wire.SessionID, header wire.FlowHeader, target string, conn net.Conn) (net.Conn, error) {
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
	if existing, ok := m.pending[key]; ok {
		if existing.role == header.Role {
			m.mu.Unlock()
			_ = conn.Close()
			return nil, fmt.Errorf("nowhere: duplicate flow half role=%d", header.Role)
		}
		delete(m.pending, key)
		if existing.timer != nil {
			existing.timer.Stop()
		}
		var openConn, attachConn net.Conn
		if header.Role == wire.FlowRoleOpen {
			openConn, attachConn = conn, existing.conn
		} else {
			openConn, attachConn = existing.conn, conn
		}
		// Server view: read client uplink (OPEN), write client downlink (ATTACH).
		paired := &splicedConn{
			reader: openConn,
			writer: attachConn,
			closer: []io.Closer{openConn, attachConn},
			remote: openConn.RemoteAddr(),
			local:  openConn.LocalAddr(),
		}
		existing.completed = true
		close(existing.done)
		m.mu.Unlock()
		return paired, nil
	}

	half := &pendingHalf{
		role: header.Role,
		conn: conn,
		done: make(chan struct{}),
	}
	half.timer = time.AfterFunc(m.timeout, func() {
		m.mu.Lock()
		cur, ok := m.pending[key]
		if !ok || cur != half {
			m.mu.Unlock()
			return
		}
		delete(m.pending, key)
		half.timedOut = true
		m.mu.Unlock()
		_ = half.conn.Close()
		close(half.done)
	})
	m.pending[key] = half
	m.mu.Unlock()

	select {
	case <-half.done:
		if half.timedOut {
			return nil, fmt.Errorf("nowhere: flow pair timeout")
		}
		// Peer completed pairing and took ownership of both halves.
		return nil, nil
	case <-ctx.Done():
		owned := false
		m.mu.Lock()
		if cur, ok := m.pending[key]; ok && cur == half {
			delete(m.pending, key)
			if half.timer != nil {
				half.timer.Stop()
			}
			owned = true
		}
		m.mu.Unlock()
		if owned {
			close(half.done)
			_ = conn.Close()
		}
		return nil, ctx.Err()
	}
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
