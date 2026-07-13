package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type fakeQuicConn struct {
	mu           sync.Mutex
	stream       QuicStream
	local        net.Addr
	remote       net.Addr
	closeCode    uint64
	closeMessage string

	closed               atomic.Int32
	acceptStreamCalls    atomic.Int32
	receiveDatagramCalls atomic.Int32
	closeWithErrorCalls  atomic.Int32
	closeCalls           atomic.Int32
}

func (c *fakeQuicConn) AcceptStream(ctx context.Context) (QuicStream, error) {
	c.acceptStreamCalls.Add(1)
	c.mu.Lock()
	stream := c.stream
	c.stream = nil
	c.mu.Unlock()
	if stream != nil {
		return stream, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (c *fakeQuicConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	c.receiveDatagramCalls.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (c *fakeQuicConn) SendDatagram([]byte) error { return nil }

func (c *fakeQuicConn) CloseWithError(code uint64, message string) error {
	c.mu.Lock()
	c.closeCode = code
	c.closeMessage = message
	c.mu.Unlock()
	c.closeWithErrorCalls.Add(1)
	c.closed.Add(1)
	return nil
}

func (c *fakeQuicConn) Close() error {
	c.closeCalls.Add(1)
	c.closed.Add(1)
	return nil
}

func (c *fakeQuicConn) Context() context.Context { return context.Background() }

func (c *fakeQuicConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return &net.UDPAddr{}
}

func (c *fakeQuicConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return &net.UDPAddr{}
}

func (c *fakeQuicConn) lastCloseWithError() (uint64, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeCode, c.closeMessage
}

type scriptedQuicConn struct {
	fakeQuicConn
	streams   chan QuicStream
	datagrams chan []byte
	sent      chan []byte
}

func newScriptedQuicConn() *scriptedQuicConn {
	conn := &scriptedQuicConn{
		streams:   make(chan QuicStream, 4),
		datagrams: make(chan []byte, 16),
		sent:      make(chan []byte, 16),
	}
	conn.local = &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443}
	conn.remote = &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 12345}
	return conn
}

func (c *scriptedQuicConn) AcceptStream(ctx context.Context) (QuicStream, error) {
	c.acceptStreamCalls.Add(1)
	select {
	case stream := <-c.streams:
		return stream, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *scriptedQuicConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	c.receiveDatagramCalls.Add(1)
	select {
	case datagram := <-c.datagrams:
		return append([]byte(nil), datagram...), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *scriptedQuicConn) SendDatagram(datagram []byte) error {
	c.sent <- append([]byte(nil), datagram...)
	return nil
}

type fakeQuicStream struct {
	reader     *bytes.Reader
	deadline   time.Time
	missingFIN bool
}

func (s *fakeQuicStream) Read(buffer []byte) (int, error) {
	n, err := s.reader.Read(buffer)
	if n == 0 && errors.Is(err, io.EOF) && s.missingFIN {
		if delay := time.Until(s.deadline); delay > 0 {
			time.Sleep(delay)
		}
		return 0, deadlineError()
	}
	return n, err
}

func (s *fakeQuicStream) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (s *fakeQuicStream) Close() error                     { return nil }

func (s *fakeQuicStream) SetDeadline(value time.Time) error {
	s.deadline = value
	return nil
}

func (s *fakeQuicStream) SetReadDeadline(value time.Time) error {
	s.deadline = value
	return nil
}

func (s *fakeQuicStream) SetWriteDeadline(time.Time) error { return nil }
func (s *fakeQuicStream) CancelRead(uint64)                {}
func (s *fakeQuicStream) CancelWrite(uint64)               {}

var (
	_ QuicConn   = (*fakeQuicConn)(nil)
	_ QuicStream = (*fakeQuicStream)(nil)
	_ io.Closer  = (*fakeQuicStream)(nil)
)
