package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Upstream receives decoded Nowhere streams / packet flows after auth + framing.
// On success the Upstream owns conn/pc lifecycle (including any CloseHandler in ctx).
type Upstream interface {
	HandleStream(ctx context.Context, conn net.Conn, source net.Addr, target string) error
	HandlePacket(ctx context.Context, pc net.PacketConn, source net.Addr, target string) error
}

type ctxKeyClose struct{}

// ContextWithCloseHandler attaches an optional CloseHandler for Upstream implementations.
func ContextWithCloseHandler(ctx context.Context, onClose CloseHandler) context.Context {
	if onClose == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyClose{}, onClose)
}

// CloseHandlerFromContext returns the CloseHandler attached by ContextWithCloseHandler.
func CloseHandlerFromContext(ctx context.Context) CloseHandler {
	h, _ := ctx.Value(ctxKeyClose{}).(CloseHandler)
	return h
}

// Dialer abstracts net.Dialer for DialUpstream.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialUpstream is a simple Portal-like upstream that dials the target and copies.
type DialUpstream struct {
	Dialer Dialer
}

// NewDialUpstream returns a DialUpstream using d, or net.Dialer if d is nil.
func NewDialUpstream(d Dialer) *DialUpstream {
	if d == nil {
		d = &net.Dialer{}
	}
	return &DialUpstream{Dialer: d}
}

func (u *DialUpstream) HandleStream(ctx context.Context, conn net.Conn, _ net.Addr, target string) error {
	remote, err := u.Dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return err // caller still owns conn / onClose
	}
	defer remote.Close()
	err = relay(conn, remote)
	if onClose := CloseHandlerFromContext(ctx); onClose != nil {
		onClose(err)
	}
	return nil // ownership taken
}

func (u *DialUpstream) HandlePacket(ctx context.Context, pc net.PacketConn, _ net.Addr, target string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	remote, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := remote.WriteTo(buf[:n], udpAddr); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, _, err := remote.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], udpAddr); err != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	var retErr error
	select {
	case <-ctx.Done():
		retErr = ctx.Err()
	case <-done:
		retErr = nil
	}
	closePacketConnWithError(pc, retErr)
	_ = remote.Close()
	<-done
	if onClose := CloseHandlerFromContext(ctx); onClose != nil {
		onClose(retErr)
	}
	return nil // ownership taken
}

func relay(a, b net.Conn) error {
	type result struct {
		direction int
		err       error
	}
	done := make(chan result, 2)
	go func() {
		_, err := io.Copy(a, b)
		done <- result{direction: 0, err: err}
	}()
	go func() {
		_, err := io.Copy(b, a)
		done <- result{direction: 1, err: err}
	}()
	first := <-done
	if first.direction == 0 {
		if closer, ok := a.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
	} else if closer, ok := b.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	timer := time.NewTimer(DefaultTCPReadGrace)
	var second result
	select {
	case second = <-done:
		timer.Stop()
	case <-timer.C:
		second.err = context.DeadlineExceeded
	}
	resultErr := first.err
	if resultErr == nil || errors.Is(resultErr, io.EOF) {
		resultErr = second.err
	}
	if errors.Is(resultErr, io.EOF) {
		resultErr = nil
	}
	closeConnWithError(a, resultErr)
	_ = b.Close()
	if second.err == context.DeadlineExceeded {
		<-done
	}
	return resultErr
}
