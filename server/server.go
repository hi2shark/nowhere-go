package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/hi2shark/nowhere-go/diagnostic"
)

var errTCPListenerConflict = errors.New("nowhere: TCP listener already installed")

type tcpListenerInstall uint8

const (
	tcpListenerInstalled tcpListenerInstall = iota
	tcpListenerReused
	tcpListenerRejected
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
	shutdown cleanupCoordinator
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
		installed, err := s.installTCPListener(listener)
		if err != nil {
			return err
		}
		if installed != tcpListenerInstalled {
			return nil
		}
		errCh := make(chan error, 2)
		go func() { errCh <- s.serveTCP(ctx, listener) }()
		if s.config.UDPEnabled() {
			go func() { errCh <- s.ServeQUIC(ctx) }()
		}
		select {
		case <-ctx.Done():
			_ = s.shutdownAndWait(ctx)
			return ctx.Err()
		case err := <-errCh:
			_ = s.shutdownAndWait(ctx)
			return err
		}
	}
	err := s.ServeQUIC(ctx)
	_ = s.shutdownAndWait(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Serve accepts raw TCP connections and delegates TLS plus protocol handling.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if err := s.validate(); err != nil {
		return err
	}
	if listener == nil {
		return fmt.Errorf("%w: nil listener", ErrInvalidConfig)
	}
	installed, err := s.installTCPListener(listener)
	if err != nil {
		return err
	}
	if installed != tcpListenerInstalled {
		return nil
	}
	return s.serveTCP(ctx, listener)
}

func (s *Server) serveTCP(ctx context.Context, listener net.Listener) error {
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

func (s *Server) installTCPListener(listener net.Listener) (tcpListenerInstall, error) {
	s.mu.Lock()
	current := s.listener
	closed := s.closed
	switch {
	case current == listener:
		s.mu.Unlock()
		return tcpListenerReused, nil
	case closed:
		s.mu.Unlock()
		_ = listener.Close()
		return tcpListenerRejected, nil
	case current != nil:
		s.mu.Unlock()
		_ = listener.Close()
		return tcpListenerRejected, errTCPListenerConflict
	default:
		s.listener = listener
		s.mu.Unlock()
		return tcpListenerInstalled, nil
	}
}

// ServeQUIC accepts QUIC connections from the injected listener.
func (s *Server) ServeQUIC(ctx context.Context) error {
	if err := s.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	listener := s.quicListener
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil
	}
	if listener == nil {
		return ErrQUICNotConfigured
	}
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			s.mu.Lock()
			closed = s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
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

func (s *Server) shutdownAndWait(ctx context.Context) error {
	_ = s.Shutdown(ctx)
	if done := s.shutdown.Done(); done != nil {
		return s.shutdown.waitDone(done)
	}
	return nil
}

// Shutdown stops new work and releases listeners and handler-owned resources.
// The initiating context is the single cleanup deadline; every caller may stop
// waiting at its own deadline while the shared cleanup continues to completion.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var listener net.Listener
	var quicListener QuicListener
	done, started := s.shutdown.start(ctx, func() {
		s.mu.Lock()
		s.closed = true
		listener = s.listener
		quicListener = s.quicListener
		s.quicListener = nil
		s.mu.Unlock()
		if s.handler != nil && s.handler.tasks != nil {
			s.handler.tasks.BeginClose()
		}
	}, func(cleanupCtx context.Context) error {
		return s.shutdownCleanup(cleanupCtx, listener, quicListener)
	})
	err := s.shutdown.wait(ctx, done)
	if started && ctx.Err() != nil && s.handler != nil {
		cause := context.Cause(ctx)
		if cause == nil {
			cause = ctx.Err()
		}
		forcedCause := markForcedTermination(cause)
		if s.handler.claims != nil {
			s.handler.claims.AbortClosing(forcedCause)
		}
		if s.handler.tasks != nil {
			s.handler.tasks.ForceDetach(forcedCause)
		}
	}
	return err
}

func (s *Server) shutdownCleanup(ctx context.Context, listener net.Listener, quicListener QuicListener) error {
	var shutdownErr error
	if listener != nil {
		shutdownErr = listener.Close()
	}
	if quicListener != nil {
		if err := quicListener.Close(); err != nil && shutdownErr == nil {
			shutdownErr = err
		}
	}
	if s.handler != nil {
		done, _ := s.handler.beginShutdown(ctx)
		if err := s.handler.shutdown.waitDone(done); err != nil {
			shutdownErr = err
		}
	}
	return shutdownErr
}

// Close applies this server's normalized shutdown timeout.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	timeout := s.config.timeouts.Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return s.Shutdown(ctx)
}

func (s *Server) validate() error {
	if s == nil || s.config == nil || s.handler == nil {
		return ErrInvalidConfig
	}
	return nil
}
