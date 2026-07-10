package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/hi2shark/go-nowhere/diagnostic"
)

// ServerOptions configures the standalone Portal-like listener orchestrator.
type ServerOptions struct {
	Config       *Config
	TLS          *tls.Config
	TLSHandshake TLSHandshaker
	Upstream     Upstream
	Observer     diagnostic.Observer
	QUICListener QuicListener
}

// Server owns listener and Handler lifecycle.
type Server struct {
	config       *Config
	handler      *Handler
	tlsHandshake TLSHandshaker
	quicListener QuicListener
	observer     diagnostic.Observer

	mu       sync.Mutex
	listener net.Listener
	closed   bool
}

// NewServer validates all required standalone dependencies.
func NewServer(options ServerOptions) (*Server, error) {
	if options.Config == nil {
		return nil, fmt.Errorf("%w: nil config", ErrInvalidConfig)
	}
	if options.Config.TCPEnabled() && options.TLSHandshake == nil && options.TLS == nil {
		return nil, ErrTLSNotConfigured
	}
	if options.Config.UDPEnabled() && options.QUICListener == nil {
		return nil, ErrQUICNotConfigured
	}
	handler, err := NewHandler(HandlerOptions{
		Config: options.Config, Upstream: options.Upstream, Observer: options.Observer,
	})
	if err != nil {
		return nil, err
	}
	handshake := options.TLSHandshake
	if handshake == nil && options.TLS != nil {
		tlsConfig := options.TLS.Clone()
		handshake = func(ctx context.Context, raw net.Conn) (net.Conn, error) {
			conn := tls.Server(raw, tlsConfig.Clone())
			if err := conn.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return conn, nil
		}
	}
	return &Server{
		config: options.Config, handler: handler, tlsHandshake: handshake,
		quicListener: options.QUICListener, observer: options.Observer,
	}, nil
}

// ListenAndServe listens on tcpAddr and serves configured carriers until cancellation.
func (s *Server) ListenAndServe(ctx context.Context, tcpAddr string) error {
	if err := s.validate(); err != nil {
		return err
	}
	if s.config.TCPEnabled() {
		listener, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.listener = listener
		s.mu.Unlock()
		errCh := make(chan error, 2)
		go func() { errCh <- s.Serve(ctx, listener) }()
		if s.config.UDPEnabled() {
			go func() { errCh <- s.ServeQUIC(ctx) }()
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
	return s.ServeQUIC(ctx)
}

// Serve accepts raw TCP connections and delegates TLS plus protocol handling.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if err := s.validate(); err != nil {
		return err
	}
	if listener == nil {
		return fmt.Errorf("%w: nil listener", ErrInvalidConfig)
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	for {
		conn, err := listener.Accept()
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
		go func(raw net.Conn) {
			_ = s.handler.ServeTCP(ctx, raw, raw.RemoteAddr(), s.tlsHandshake, nil)
		}(conn)
	}
}

// ServeQUIC accepts QUIC connections from the injected listener.
func (s *Server) ServeQUIC(ctx context.Context) error {
	if err := s.validate(); err != nil {
		return err
	}
	if s.quicListener == nil {
		return ErrQUICNotConfigured
	}
	for {
		conn, err := s.quicListener.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				diagnostic.Emit(ctx, s.observer, diagnostic.Event{
					Level: diagnostic.LevelWarn, Code: "quic_accept_failed", Component: "server", Err: err,
				})
				continue
			}
		}
		go func() { _ = s.handler.ServeQUIC(ctx, conn) }()
	}
}

// Close shuts down listeners and all manager-owned state.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	listener := s.listener
	s.listener = nil
	s.mu.Unlock()
	var closeErr error
	if listener != nil {
		closeErr = listener.Close()
	}
	if s.handler != nil {
		_ = s.handler.Close()
	}
	if s.quicListener != nil {
		if err := s.quicListener.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func (s *Server) validate() error {
	if s == nil || s.config == nil || s.handler == nil {
		return ErrInvalidConfig
	}
	return nil
}
