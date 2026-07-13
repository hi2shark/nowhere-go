package server

import (
	"context"
	"io"
	"net"

	"github.com/hi2shark/nowhere-go/wire"
)

func (s *portalSession) datagramLoop(ctx context.Context, pending [][]byte) {
	for _, data := range pending {
		s.handleDatagram(ctx, data)
	}
	for {
		data, err := s.Conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		s.handleDatagram(ctx, data)
	}
}

func (s *portalSession) handleDatagram(ctx context.Context, data []byte) {
	if len(data) >= 2 && data[1] >= wire.UDPTypeOpenData && data[1] <= wire.UDPTypeCompactClose {
		if frame, err := wire.DecodeUDPCompact(data); err == nil && validCompactIngress(frame) {
			s.handleCompactFrame(ctx, frame)
			return
		}
	}

	message, err := wire.DecodeUDPDatagram(data, s.Handler.config.spec)
	if err != nil || (message.Type != wire.UDPTypeRequest && message.Type != wire.UDPTypeClose) {
		return
	}
	s.handleLegacyDatagram(ctx, message)
}

func validCompactIngress(frame wire.CompactUDPFrame) bool {
	switch frame.Type {
	case wire.UDPTypeOpenData, wire.UDPTypeData, wire.UDPTypeCompactClose:
		return true
	default:
		return false
	}
}

func (s *portalSession) handleLegacyDatagram(ctx context.Context, message *wire.UDPMessage) {
	if message == nil {
		return
	}
	key := legacyUDPKey{flowID: message.FlowID, target: message.Target}
	switch message.Type {
	case wire.UDPTypeRequest:
		if flow := s.getLegacyFlow(key); flow != nil {
			flow.deliver(message.Payload)
			return
		}

		flow := newLegacyUDPFlow(s, key)
		if !s.reserveLegacyFlow(flow) {
			flow.shutdown(net.ErrClosed)
			if existing := s.getLegacyFlow(key); existing != nil {
				existing.deliver(message.Payload)
			}
			return
		}
		flow.deliver(message.Payload)
		flowCtx := ContextWithCloseHandler(ctx, flow.shutdown)
		go func() { _ = s.Handler.routePacket(flowCtx, flow, s.Source, message.Target) }()
	case wire.UDPTypeClose:
		if flow := s.getLegacyFlow(key); flow != nil {
			flow.shutdown(io.EOF)
		}
	}
}
