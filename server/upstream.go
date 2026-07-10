package server

import (
	"context"
	"io"
	"net"
	"sync"
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
	_ = pc.Close()
	_ = remote.Close()
	<-done
	if onClose := CloseHandlerFromContext(ctx); onClose != nil {
		onClose(retErr)
	}
	return nil // ownership taken
}

func relay(a, b net.Conn) error {
	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(a, b)
		done <- err
	}()
	go func() {
		_, err := io.Copy(b, a)
		done <- err
	}()
	err := <-done
	_ = a.Close()
	_ = b.Close()
	<-done
	if err == io.EOF {
		return nil
	}
	return err
}
