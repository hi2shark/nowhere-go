package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/diagnostic"
	"github.com/hi2shark/nowhere-go/wire"
)

// TLSHandshaker lets a host retain ownership of its TLS policy and implementation.
type TLSHandshaker func(context.Context, net.Conn) (net.Conn, error)

// HandlerOptions builds a valid Handler and its internal state managers.
type HandlerOptions struct {
	Config   *Config
	Upstream Upstream
	Observer diagnostic.Observer
}

// Handler authenticates carriers and hands decoded flows to Upstream.
type Handler struct {
	config    *Config
	upstream  Upstream
	observer  diagnostic.Observer
	pairing   *flowPairManager
	sessions  *sessionManager
	admission *unauthenticatedAdmission
	handshake *handshakeGate
	now       func() time.Time
	randRead  func([]byte) (int, error)

	admissionLogMu   sync.Mutex
	admissionLastLog time.Time
	admissionSkipped int
}

// NewHandler constructs a handler whose internal state is always initialized.
func NewHandler(options HandlerOptions) (*Handler, error) {
	if options.Config == nil || options.Config.spec == nil {
		return nil, fmt.Errorf("%w: nil config", ErrInvalidHandler)
	}
	if options.Upstream == nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidHandler, ErrUpstreamNotConfigured)
	}
	h := &Handler{
		config:   options.Config,
		upstream: options.Upstream,
		observer: options.Observer,
		pairing:  newFlowPairManager(options.Config.timeouts.FlowPair),
		sessions: newSessionManager(),
		admission: newUnauthenticatedAdmission(
			options.Config.limits.MaxUnauthenticatedConnections,
			options.Config.limits.MaxUnauthenticatedPerSource,
		),
		handshake: newHandshakeGate(options.Config.limits.MaxConcurrentHandshakes),
		now:       time.Now,
		randRead:  rand.Read,
	}
	h.pairing.configureLimits(options.Config.limits)
	h.pairing.setObserver(options.Observer)
	h.sessions.configureLimit(options.Config.limits.ActiveQUICSessions)
	return h, nil
}

// Close releases all pending pairs and authenticated sessions.
// It is safe to call more than once.
func (h *Handler) Close() error {
	if h == nil {
		return nil
	}
	if h.pairing != nil {
		h.pairing.Close()
	}
	if h.sessions != nil {
		h.sessions.Close()
	}
	return nil
}

// ServeTCP performs the host TLS handshake on a raw TCP carrier, authenticates,
// and routes exactly one request. On successful handoff Upstream owns the wrapped conn.
func (h *Handler) ServeTCP(ctx context.Context, raw net.Conn, source net.Addr, handshake TLSHandshaker, onClose CloseHandler) error {
	if err := h.validate(); err != nil {
		if raw != nil {
			_ = raw.Close()
		}
		return err
	}
	if raw == nil {
		return fmt.Errorf("%w: nil tcp connection", ErrInvalidHandler)
	}
	life := newLifecycle(ctx, raw, onClose, h.observer)
	guard, ok := h.admission.tryAcquire(source)
	if !ok {
		life.Close(ErrAdmissionLimit)
		h.emitAdmissionLimited(ctx, source)
		return report(ErrAdmissionLimit)
	}
	releaseAdmission := guard.Release
	defer releaseAdmission()

	if handshake == nil {
		life.Close(ErrTLSNotConfigured)
		return ErrTLSNotConfigured
	}
	releaseHandshake, err := h.handshake.acquire(ctx)
	if err != nil {
		life.Close(err)
		return report(err)
	}

	handshakeCtx, cancel := context.WithTimeout(ctx, h.config.timeouts.TLSHandshake)
	conn, err := handshake(handshakeCtx, raw)
	cancel()
	releaseHandshake()
	if err != nil {
		life.Close(err)
		h.emit(ctx, classifyTLSHandshake(err), "tls_handshake_failed", source, "", wire.SessionID{}, 0, err)
		return report(err)
	}
	if conn == nil {
		err = fmt.Errorf("%w: TLS handshaker returned nil conn", ErrInvalidHandler)
		life.Close(err)
		return err
	}
	owned := &ownedConn{Conn: conn, life: life}
	return h.handleTCPConn(ctx, owned, source, releaseAdmission)
}

// HandleConn handles an already handshaked carrier. Hosts should prefer ServeTCP
// when they can provide a TLSHandshaker so its deadline also covers the handshake.
func (h *Handler) HandleConn(ctx context.Context, conn net.Conn, source net.Addr, onClose CloseHandler) error {
	return h.ServeTCP(ctx, conn, source, func(_ context.Context, conn net.Conn) (net.Conn, error) {
		return conn, nil
	}, onClose)
}

func (h *Handler) handleTCPConn(ctx context.Context, conn *ownedConn, source net.Addr, releaseAdmission func()) error {
	deadline := h.authDeadline()
	_ = conn.SetDeadline(deadline)
	br := bufio.NewReader(conn)
	stream := &bufferedConn{Conn: conn, reader: br}

	sessionID, err := wire.ReadAuthFrame(stream, h.config.key, h.config.spec)
	if err != nil {
		h.waitAuthFailure(ctx, deadline)
		conn.closeWithError(err)
		h.emit(ctx, diagnostic.LevelError, "auth_failed", source, "", wire.SessionID{}, 0, err)
		return report(err)
	}
	if releaseAdmission != nil {
		releaseAdmission()
	}
	_ = conn.SetDeadline(time.Time{})
	_ = conn.SetReadDeadline(h.now().Add(h.config.timeouts.RequestIdle))

	peek, err := br.Peek(1)
	if err != nil {
		conn.closeWithError(err)
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, net.ErrClosed) {
			h.emit(ctx, diagnostic.LevelError, "request_read_failed", source, "", sessionID, 0, err)
			return report(err)
		}
		return err
	}

	var header *wire.FlowHeader
	if peek[0] == wire.FlowFrameMagic {
		fh, readErr := wire.ReadFlowHeader(stream)
		if readErr != nil {
			conn.closeWithError(readErr)
			return readErr
		}
		header = &fh
	}
	target, err := wire.DecodeTCPRequest(stream, h.config.spec)
	if err != nil {
		conn.closeWithError(err)
		return err
	}
	_ = conn.SetDeadline(time.Time{})

	if header != nil {
		return h.handleAsymmetric(ctx, stream, source, sessionID, *header, target)
	}
	if target == wire.UOTMagicTarget {
		return h.handleUOT(ctx, stream, source)
	}
	return h.routeStream(ctx, stream, source, target)
}

func (h *Handler) handleUOT(ctx context.Context, conn net.Conn, source net.Addr) error {
	_ = conn.SetReadDeadline(h.now().Add(h.config.timeouts.UOTSetup))
	target, err := wire.ReadUOTSetupTarget(conn)
	if err != nil {
		closeConnWithError(conn, err)
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	pc := newUOTPacketConn(conn, parseTargetAddr(target))
	pc.SetIdleTimeout(h.config.timeouts.UDPIdle)
	return h.routePacket(ctx, pc, source, target)
}

func (h *Handler) handleAsymmetric(ctx context.Context, conn net.Conn, source net.Addr, sessionID wire.SessionID, header wire.FlowHeader, target string) error {
	switch header.Kind {
	case wire.FlowKindTCP:
		return h.handleAsymmetricTCP(ctx, conn, source, sessionID, header, target)
	case wire.FlowKindUDP:
		return h.handleAsymmetricUDPStream(ctx, conn, source, sessionID, header, target)
	default:
		err := fmt.Errorf("%w: invalid flow kind", ErrUnsupportedFlow)
		closeConnWithError(conn, err)
		return err
	}
}

func (h *Handler) handleAsymmetricTCP(ctx context.Context, conn net.Conn, source net.Addr, sessionID wire.SessionID, header wire.FlowHeader, target string) error {
	paired, err := h.pairing.SubmitTCPWithSource(ctx, sessionID, header, target, conn, source)
	if err != nil {
		closeConnWithError(conn, err)
		return err
	}
	if paired == nil {
		return nil
	}
	return h.routeStream(ctx, paired, source, target)
}

func (h *Handler) handleAsymmetricUDPStream(ctx context.Context, conn net.Conn, source net.Addr, sessionID wire.SessionID, header wire.FlowHeader, target string) error {
	var half udpHalf
	half.Role = header.Role
	switch header.Role {
	case wire.FlowRoleOpen:
		if header.Uplink != wire.CarrierTCP {
			err := fmt.Errorf("%w: UDP OPEN on TLS requires tcp uplink", ErrCarrierMismatch)
			closeConnWithError(conn, err)
			return err
		}
		half.Uplink = newTCPUDPUplink(conn)
	case wire.FlowRoleAttach:
		if header.Downlink != wire.CarrierTCP {
			err := fmt.Errorf("%w: UDP ATTACH on TLS requires tcp downlink", ErrCarrierMismatch)
			closeConnWithError(conn, err)
			return err
		}
		half.Downlink = newTCPUDPDownlink(conn)
	default:
		err := fmt.Errorf("%w: invalid flow role", ErrUnsupportedFlow)
		closeConnWithError(conn, err)
		return err
	}
	return h.submitAndRouteUDP(ctx, source, sessionID, header, target, half)
}

func (h *Handler) submitAndRouteUDP(ctx context.Context, source net.Addr, sessionID wire.SessionID, header wire.FlowHeader, target string, half udpHalf) error {
	handle, paired, err := h.pairing.SubmitUDPWithSource(ctx, sessionID, header, target, half, source, udpHalfTransport(header, half))
	if err != nil {
		closeUDPHalfWithError(half, err)
		return err
	}
	if paired == nil {
		return nil
	}
	paired.IdleTimeout = h.config.timeouts.UDPIdle
	conn := newPairedUDPConn(paired)
	conn.setFinish(func(cause error) { h.pairing.finishUDP(handle, cause) })
	if !h.pairing.bindUDP(handle, conn) {
		if cause := handle.Err(); cause != nil {
			return cause
		}
		return ErrClosed
	}
	return h.routePacket(ctx, conn, source, target)
}

func (h *Handler) handleStreamRequest(ctx context.Context, conn net.Conn, source net.Addr, sessionID wire.SessionID, header *wire.FlowHeader, target string) error {
	if header != nil {
		return h.handleAsymmetric(ctx, conn, source, sessionID, *header, target)
	}
	if target == wire.UOTMagicTarget {
		return h.handleUOT(ctx, conn, source)
	}
	return h.routeStream(ctx, conn, source, target)
}

func (h *Handler) routeStream(ctx context.Context, conn net.Conn, source net.Addr, target string) error {
	if h == nil || h.upstream == nil {
		closeConnWithError(conn, ErrUpstreamNotConfigured)
		return ErrUpstreamNotConfigured
	}
	if closeHandler := closeHandlerForConn(conn); closeHandler != nil {
		ctx = ContextWithCloseHandler(ctx, closeHandler)
	}
	if err := h.upstream.HandleStream(ctx, conn, source, target); err != nil {
		closeConnWithError(conn, err)
		h.emit(ctx, diagnostic.LevelWarn, "upstream_stream_failed", source, target, wire.SessionID{}, 0, err)
		return report(err)
	}
	return nil
}

func (h *Handler) routePacket(ctx context.Context, pc net.PacketConn, source net.Addr, target string) error {
	if h == nil || h.upstream == nil {
		_ = pc.Close()
		return ErrUpstreamNotConfigured
	}
	if closeHandler := closeHandlerForPacketConn(pc); closeHandler != nil {
		ctx = ContextWithCloseHandler(ctx, closeHandler)
	}
	if err := h.upstream.HandlePacket(ctx, pc, source, target); err != nil {
		closePacketConnWithError(pc, err)
		h.emit(ctx, diagnostic.LevelWarn, "upstream_packet_failed", source, target, wire.SessionID{}, 0, err)
		return report(err)
	}
	return nil
}

func (h *Handler) validate() error {
	if h == nil || h.config == nil || h.config.spec == nil || h.pairing == nil || h.sessions == nil {
		return ErrInvalidHandler
	}
	if h.upstream == nil {
		return ErrUpstreamNotConfigured
	}
	return nil
}

func (h *Handler) authDeadline() time.Time {
	var raw [8]byte
	factor := 1.0
	if _, err := h.randRead(raw[:]); err == nil {
		ratio := float64(binary.BigEndian.Uint64(raw[:])) / float64(^uint64(0))
		factor = 0.8 + ratio*0.4
	}
	return h.now().Add(time.Duration(float64(h.config.timeouts.Auth) * factor))
}

func (h *Handler) waitAuthFailure(ctx context.Context, deadline time.Time) {
	delay := deadline.Sub(h.now())
	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (h *Handler) emit(ctx context.Context, level diagnostic.Level, code string, source net.Addr, target string, sessionID wire.SessionID, flowID uint64, err error) {
	result, class := "", ""
	if err != nil {
		result, class = diagnostic.ClassifyClose(err)
	}
	diagnostic.Emit(ctx, h.observer, diagnostic.Event{
		Level: level, Code: code, Component: "server", Carrier: diagnostic.CarrierTCPTLS,
		Source: source, Target: target, SessionID: sessionID, FlowID: flowID,
		Result: result, ErrorClass: class, Err: err,
	})
}

func (h *Handler) emitAdmissionLimited(ctx context.Context, source net.Addr) {
	h.admissionLogMu.Lock()
	now := h.now()
	if !h.admissionLastLog.IsZero() && now.Sub(h.admissionLastLog) < time.Second {
		h.admissionSkipped++
		h.admissionLogMu.Unlock()
		return
	}
	skipped := h.admissionSkipped
	h.admissionSkipped = 0
	h.admissionLastLog = now
	h.admissionLogMu.Unlock()

	outcome := ""
	if skipped > 0 {
		outcome = fmt.Sprintf("suppressed=%d", skipped)
	}
	diagnostic.Emit(ctx, h.observer, diagnostic.Event{
		Level: diagnostic.LevelWarn, Code: "admission_limited", Component: "server",
		Source: source, Outcome: outcome, Err: ErrAdmissionLimit,
	})
}

func classifyTLSHandshake(err error) diagnostic.Level {
	if err == nil {
		return diagnostic.LevelError
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return diagnostic.LevelWarn
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return diagnostic.LevelWarn
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return diagnostic.LevelDebug
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "use of closed network connection"):
		return diagnostic.LevelDebug
	default:
		return diagnostic.LevelError
	}
}

func closeConnWithError(conn net.Conn, err error) {
	if owned, ok := conn.(*ownedConn); ok {
		owned.closeWithError(err)
		return
	}
	if buffered, ok := conn.(*bufferedConn); ok {
		closeConnWithError(buffered.Conn, err)
		return
	}
	if spliced, ok := conn.(*splicedConn); ok {
		spliced.closeWithError(err)
		return
	}
	if conn != nil {
		_ = conn.Close()
	}
}

func closePacketConnWithError(pc net.PacketConn, err error) {
	if owned, ok := pc.(*ownedPacketConn); ok {
		owned.closeWithError(err)
		return
	}
	if paired, ok := pc.(*pairedUDPConn); ok {
		paired.closeWithError(err)
		return
	}
	if uot, ok := pc.(*uotPacketConn); ok {
		uot.closeWithError(err)
		return
	}
	if compact, ok := pc.(*compactUDPFlow); ok {
		compact.closeWithError(err)
		return
	}
	if pc != nil {
		_ = pc.Close()
	}
}

func lifecycleFromConn(conn net.Conn) *lifecycle {
	switch value := conn.(type) {
	case *ownedConn:
		return value.life
	case *bufferedConn:
		return lifecycleFromConn(value.Conn)
	}
	return nil
}

func lifecycleFromPacketConn(pc net.PacketConn) *lifecycle {
	if value, ok := pc.(*ownedPacketConn); ok {
		return value.life
	}
	if value, ok := pc.(*uotPacketConn); ok {
		return lifecycleFromConn(value.Conn)
	}
	return nil
}

func closeHandlerForConn(conn net.Conn) CloseHandler {
	if life := lifecycleFromConn(conn); life != nil {
		return life.Close
	}
	if spliced, ok := conn.(*splicedConn); ok {
		return spliced.closeWithError
	}
	return nil
}

func closeHandlerForPacketConn(pc net.PacketConn) CloseHandler {
	if life := lifecycleFromPacketConn(pc); life != nil {
		return life.Close
	}
	switch value := pc.(type) {
	case *pairedUDPConn:
		return value.closeWithError
	case *compactUDPFlow:
		return value.shutdown
	}
	return nil
}

func parseTargetAddr(target string) net.Addr {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return &addrString{s: target}
	}
	if ip := net.ParseIP(host); ip != nil {
		var p int
		if _, err := fmt.Sscanf(port, "%d", &p); err != nil {
			return &addrString{s: target}
		}
		return &net.UDPAddr{IP: ip, Port: p}
	}
	return &addrString{s: target}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
