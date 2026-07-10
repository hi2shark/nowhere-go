package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
)

// ErrQUICNotConfigured is returned when UDP/QUIC is enabled but no QuicListener is injected.
var ErrQUICNotConfigured = errors.New("nowhere: QUIC enabled but no QuicListener injected")

// Server is a Portal-like Nowhere listener orchestrator.
type Server struct {
	Config   *Config
	TLS      *tls.Config
	Upstream Upstream
	Handler  *Handler
	Logger   Logger

	// QuicListener is optional; required when Config.EnableUDP is true.
	QuicListener QuicListener

	mu       sync.Mutex
	listener net.Listener
	closed   bool
}

// NewServer builds a Server. Pairing / Sessions are created if nil on Handler.
// upstream must be non-nil.
func NewServer(cfg *Config, tlsCfg *tls.Config, upstream Upstream) *Server {
	if upstream == nil {
		panic("nowhere: NewServer requires non-nil Upstream")
	}
	pairing := NewFlowPairManager(cfg.FlowPairTimeout)
	sessions := NewSessionManager()
	h := &Handler{
		Config:   cfg,
		Upstream: upstream,
		Pairing:  pairing,
		Sessions: sessions,
	}
	return &Server{
		Config:   cfg,
		TLS:      tlsCfg,
		Upstream: upstream,
		Handler:  h,
	}
}

// ListenAndServe listens on tcpAddr and serves until ctx is cancelled or Close.
func (s *Server) ListenAndServe(ctx context.Context, tcpAddr string) error {
	if s.Config.EnableTCP {
		ln, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.listener = ln
		s.mu.Unlock()
		errCh := make(chan error, 2)
		go func() {
			errCh <- s.Serve(ctx, ln)
		}()
		if s.Config.EnableUDP {
			go func() {
				errCh <- s.ServeQUIC(ctx)
			}()
		}
		select {
		case <-ctx.Done():
			_ = s.Close()
			return ctx.Err()
		case err := <-errCh:
			_ = s.Close()
			return err
		}
	}
	if s.Config.EnableUDP {
		return s.ServeQUIC(ctx)
	}
	return fmt.Errorf("nowhere: no networks enabled")
}

// Serve accepts TCP connections, performs TLS handshake, then HandleConn.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	s.Handler.Logger = resolveLogger(s.Logger)
	if s.Handler.Upstream == nil {
		s.Handler.Upstream = s.Upstream
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}
		go s.handleTCP(ctx, conn)
	}
}

func (s *Server) handleTCP(ctx context.Context, conn net.Conn) {
	log := resolveLogger(s.Logger)
	tlsCfg := s.TLS
	if tlsCfg == nil {
		_ = conn.Close()
		log.Errorf("nowhere: missing tls.Config")
		return
	}
	tlsConn := tls.Server(conn, tlsCfg.Clone())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		log.Errorf("nowhere tls handshake from %v: %v", conn.RemoteAddr(), err)
		return
	}
	s.Handler.HandleConn(ctx, tlsConn, tlsConn.RemoteAddr())
}

// ServeQUIC accepts QuicConn from the injected QuicListener.
func (s *Server) ServeQUIC(ctx context.Context) error {
	if s.QuicListener == nil {
		return ErrQUICNotConfigured
	}
	s.Handler.Logger = resolveLogger(s.Logger)
	if s.Handler.Upstream == nil {
		s.Handler.Upstream = s.Upstream
	}
	for {
		conn, err := s.QuicListener.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				resolveLogger(s.Logger).Debugf("nowhere quic accept: %v", err)
				continue
			}
		}
		go s.Handler.ServeQuicConn(ctx, conn)
	}
}

// Close shuts down the TCP listener, pairing, and sessions.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.listener
	s.listener = nil
	s.mu.Unlock()
	var err error
	if ln != nil {
		err = ln.Close()
	}
	if s.Handler != nil {
		if s.Handler.Pairing != nil {
			s.Handler.Pairing.Close()
		}
		if s.Handler.Sessions != nil {
			s.Handler.Sessions.Close()
		}
	}
	if s.QuicListener != nil {
		if e := s.QuicListener.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}
