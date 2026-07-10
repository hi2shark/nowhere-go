package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/hi2shark/go-nowhere/wire"
)

// CloseHandler is an optional callback invoked when a connection fails or closes.
type CloseHandler func(error)

// Handler routes decoded Nowhere flows to Upstream after auth + framing.
type Handler struct {
	Config   *Config
	Upstream Upstream
	Logger   Logger
	Pairing  *FlowPairManager
	Sessions *SessionManager
}

// HandleConn processes one authenticated TLS/TCP (or already-handshaked) carrier.
func (h *Handler) HandleConn(ctx context.Context, conn net.Conn, source net.Addr) {
	h.HandleConnWithClose(ctx, conn, source, nil)
}

// HandleConnWithClose is HandleConn with an optional close callback.
func (h *Handler) HandleConnWithClose(ctx context.Context, conn net.Conn, source net.Addr, onClose CloseHandler) {
	log := resolveLogger(h.Logger)
	br := bufio.NewReader(conn)
	stream := &bufferedConn{Conn: conn, reader: br}

	sessionID, err := wire.ReadAuthFrame(stream, h.Config.Key, h.Config.Spec)
	if err != nil {
		closeOnFailure(conn, onClose, err)
		log.Errorf("nowhere auth from %v: %v", source, err)
		return
	}

	peek, err := br.Peek(1)
	if err != nil {
		closeOnFailure(conn, onClose, err)
		// Idle pool teardown after auth commonly yields EOF; not a protocol fault.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
			log.Debugf("nowhere carrier closed after auth from %v: %v", source, err)
			return
		}
		log.Errorf("nowhere peek request from %v: %v", source, err)
		return
	}

	var header *wire.FlowHeader
	if peek[0] == wire.FlowFrameMagic {
		fh, err := wire.ReadFlowHeader(stream)
		if err != nil {
			closeOnFailure(conn, onClose, err)
			log.Errorf("nowhere flow header from %v: %v", source, err)
			return
		}
		header = &fh
	}

	target, err := wire.DecodeTCPRequest(stream, h.Config.Spec)
	if err != nil {
		closeOnFailure(conn, onClose, err)
		log.Errorf("nowhere tcp request from %v: %v", source, err)
		return
	}

	if header != nil {
		h.handleAsymmetric(ctx, stream, source, sessionID, *header, target, onClose)
		return
	}

	if target == wire.UOTMagicTarget {
		h.handleUOT(ctx, stream, source, onClose)
		return
	}

	log.Infof("inbound connection to %s", target)
	h.routeStream(ctx, stream, source, target, onClose)
}

func (h *Handler) handleUOT(ctx context.Context, conn net.Conn, source net.Addr, onClose CloseHandler) {
	log := resolveLogger(h.Logger)
	target, err := wire.ReadUOTSetupTarget(conn)
	if err != nil {
		closeOnFailure(conn, onClose, err)
		log.Errorf("nowhere uot setup from %v: %v", source, err)
		return
	}
	dest := parseTargetAddr(target)
	log.Infof("inbound packet connection to %s", target)
	pc := NewUOTPacketConn(conn, dest)
	h.routePacket(ctx, pc, source, target, onClose)
}

func (h *Handler) handleAsymmetric(ctx context.Context, conn net.Conn, source net.Addr, sessionID wire.SessionID, header wire.FlowHeader, target string, onClose CloseHandler) {
	if h.Pairing == nil {
		closeOnFailure(conn, onClose, fmt.Errorf("nowhere: asymmetric flow not supported"))
		return
	}
	switch header.Kind {
	case wire.FlowKindTCP:
		h.handleAsymmetricTCP(ctx, conn, source, sessionID, header, target, onClose)
	case wire.FlowKindUDP:
		h.handleAsymmetricUDPStream(ctx, conn, source, sessionID, header, target, onClose)
	default:
		closeOnFailure(conn, onClose, fmt.Errorf("nowhere: invalid flow kind"))
	}
}

func (h *Handler) handleAsymmetricTCP(ctx context.Context, conn net.Conn, source net.Addr, sessionID wire.SessionID, header wire.FlowHeader, target string, onClose CloseHandler) {
	log := resolveLogger(h.Logger)
	paired, err := h.Pairing.SubmitTCP(ctx, sessionID, header, target, conn)
	if err != nil {
		closeOnFailure(conn, onClose, err)
		log.Errorf("nowhere flow pair from %v: %v", source, err)
		return
	}
	if paired == nil {
		return
	}
	log.Infof("inbound asymmetric connection to %s", target)
	h.routeStream(ctx, paired, source, target, onClose)
}

func (h *Handler) handleAsymmetricUDPStream(ctx context.Context, conn net.Conn, source net.Addr, sessionID wire.SessionID, header wire.FlowHeader, target string, onClose CloseHandler) {
	var half UDPHalf
	half.Role = header.Role
	switch header.Role {
	case wire.FlowRoleOpen:
		if header.Uplink != wire.CarrierTCP {
			closeOnFailure(conn, onClose, fmt.Errorf("nowhere: UDP OPEN on TLS requires tcp uplink"))
			return
		}
		half.Uplink = NewTCPUDPUplink(conn)
	case wire.FlowRoleAttach:
		if header.Downlink != wire.CarrierTCP {
			closeOnFailure(conn, onClose, fmt.Errorf("nowhere: UDP ATTACH on TLS requires tcp downlink"))
			return
		}
		half.Downlink = NewTCPUDPDownlink(conn)
	default:
		closeOnFailure(conn, onClose, fmt.Errorf("nowhere: invalid flow role"))
		return
	}
	h.SubmitAndRouteUDP(ctx, source, sessionID, header, target, half, onClose)
}

// SubmitAndRouteUDP pairs a UDP half and routes the completed PacketConn upstream.
func (h *Handler) SubmitAndRouteUDP(ctx context.Context, source net.Addr, sessionID wire.SessionID, header wire.FlowHeader, target string, half UDPHalf, onClose CloseHandler) {
	log := resolveLogger(h.Logger)
	paired, err := h.Pairing.SubmitUDP(ctx, sessionID, header, target, half)
	if err != nil {
		closeUDPHalf(half)
		if onClose != nil {
			onClose(err)
		}
		log.Errorf("nowhere udp flow pair from %v: %v", source, err)
		return
	}
	if paired == nil {
		return
	}
	log.Infof("inbound asymmetric packet connection to %s", target)
	pc := NewPairedUDPConn(paired)
	h.routePacket(ctx, pc, source, target, onClose)
}

// HandleStreamRequest processes a post-auth QUIC stream (flow header + TCP request already peekable).
func (h *Handler) HandleStreamRequest(ctx context.Context, conn net.Conn, source net.Addr, sessionID wire.SessionID, header *wire.FlowHeader, target string, onClose CloseHandler) {
	log := resolveLogger(h.Logger)
	if header != nil {
		h.handleAsymmetric(ctx, conn, source, sessionID, *header, target, onClose)
		return
	}
	if target == wire.UOTMagicTarget {
		h.handleUOT(ctx, conn, source, onClose)
		return
	}
	log.Infof("inbound connection to %s", target)
	h.routeStream(ctx, conn, source, target, onClose)
}

// routeStream hands conn to Upstream; on success Upstream owns onClose.
func (h *Handler) routeStream(ctx context.Context, conn net.Conn, source net.Addr, target string, onClose CloseHandler) {
	log := resolveLogger(h.Logger)
	if h.Upstream == nil {
		err := fmt.Errorf("nowhere: nil Upstream")
		closeOnFailure(conn, onClose, err)
		log.Errorf("nowhere upstream stream %s: %v", target, err)
		return
	}
	ctx = ContextWithCloseHandler(ctx, onClose)
	if err := h.Upstream.HandleStream(ctx, conn, source, target); err != nil {
		closeOnFailure(conn, onClose, err)
		log.Errorf("nowhere upstream stream %s: %v", target, err)
	}
}

func (h *Handler) routePacket(ctx context.Context, pc net.PacketConn, source net.Addr, target string, onClose CloseHandler) {
	log := resolveLogger(h.Logger)
	if h.Upstream == nil {
		err := fmt.Errorf("nowhere: nil Upstream")
		_ = pc.Close()
		if onClose != nil {
			onClose(err)
		}
		log.Errorf("nowhere upstream packet %s: %v", target, err)
		return
	}
	ctx = ContextWithCloseHandler(ctx, onClose)
	if err := h.Upstream.HandlePacket(ctx, pc, source, target); err != nil {
		_ = pc.Close()
		if onClose != nil {
			onClose(err)
		}
		log.Errorf("nowhere upstream packet %s: %v", target, err)
	}
}

func closeOnFailure(conn net.Conn, onClose CloseHandler, err error) {
	if conn != nil {
		_ = conn.Close()
	}
	if onClose != nil {
		onClose(err)
	}
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

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
