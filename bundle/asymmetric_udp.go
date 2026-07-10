package bundle

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/hi2shark/go-nowhere/carrier"
	"github.com/hi2shark/go-nowhere/wire"
)

func (b *CarrierBundle) AsymmetricOpenUDP(ctx context.Context, dest string) (net.PacketConn, error) {
	up, down := b.UpCarrier(), b.DownCarrier()
	flowID := b.allocFlowID()

	var quicFlow carrier.QuicUDPFlow
	var quicSession carrier.QuicSession
	if up == wire.CarrierUDP || down == wire.CarrierUDP {
		client, err := b.quicClient()
		if err != nil {
			return nil, err
		}
		if client == nil {
			return nil, errors.New("nowhere: udp carrier unavailable")
		}
		s, err := client.AcquireSession(ctx)
		if err != nil {
			return nil, err
		}
		if err := s.EnsureReady(ctx); err != nil {
			return nil, err
		}
		quicFlow, err = s.RegisterUDPAsymmetricFlow(ctx, dest, flowID)
		if err != nil {
			return nil, err
		}
		quicSession = s
	}

	var uplink udpUplink
	var upCloser io.Closer
	switch up {
	case wire.CarrierUDP:
		uplink = &quicUDPUplink{client: b.quicClientSync(), session: quicSession, flow: quicFlow, target: dest, down: down}
	case wire.CarrierTCP:
		pool, err := b.tcpPool()
		if err != nil {
			b.releaseQUICFlow(quicSession, quicFlow)
			return nil, err
		}
		if pool == nil {
			b.releaseQUICFlow(quicSession, quicFlow)
			return nil, errors.New("nowhere: tcp uplink carrier unavailable")
		}
		header := wire.FlowHeader{Role: wire.FlowRoleOpen, FlowID: flowID, Kind: wire.FlowKindUDP, Uplink: up, Downlink: down}
		conn, err := pool.AcquireUDPFlowHalf(ctx, dest, header)
		if err != nil {
			b.releaseQUICFlow(quicSession, quicFlow)
			return nil, err
		}
		uplink = &uotLaneUplink{raw: conn}
		upCloser = conn
	}

	var downlink udpDownlink
	var dnCloser io.Closer
	switch down {
	case wire.CarrierUDP:
		// tcp/udp: ATTACH stream is pairing-only; DATAGRAM carries data.
		if up == wire.CarrierTCP {
			client := b.quicClientSync()
			if client == nil {
				_ = uplink.ClosePacket()
				if upCloser != nil {
					_ = upCloser.Close()
				}
				b.releaseQUICFlow(quicSession, quicFlow)
				return nil, errors.New("nowhere: udp downlink carrier unavailable")
			}
			header := wire.FlowHeader{Role: wire.FlowRoleAttach, FlowID: flowID, Kind: wire.FlowKindUDP, Uplink: up, Downlink: down}
			attach, err := client.OpenFlowStream(ctx, dest, header)
			if err != nil {
				_ = uplink.ClosePacket()
				if upCloser != nil {
					_ = upCloser.Close()
				}
				b.releaseQUICFlow(quicSession, quicFlow)
				return nil, err
			}
			dnCloser = attach
		}
		downlink = &quicUDPDownlink{flow: quicFlow}
	case wire.CarrierTCP:
		pool, err := b.tcpPool()
		if err != nil {
			_ = uplink.ClosePacket()
			if upCloser != nil {
				_ = upCloser.Close()
			}
			b.releaseQUICFlow(quicSession, quicFlow)
			return nil, err
		}
		if pool == nil {
			_ = uplink.ClosePacket()
			if upCloser != nil {
				_ = upCloser.Close()
			}
			b.releaseQUICFlow(quicSession, quicFlow)
			return nil, errors.New("nowhere: tcp downlink carrier unavailable")
		}
		header := wire.FlowHeader{Role: wire.FlowRoleAttach, FlowID: flowID, Kind: wire.FlowKindUDP, Uplink: up, Downlink: down}
		conn, err := pool.AcquireUDPFlowHalf(ctx, dest, header)
		if err != nil {
			_ = uplink.ClosePacket()
			if upCloser != nil {
				_ = upCloser.Close()
			}
			b.releaseQUICFlow(quicSession, quicFlow)
			return nil, err
		}
		downlink = &uotLaneDownlink{raw: conn}
		dnCloser = conn
	}

	return &asymmetricPacketConn{
		dest:     dest,
		uplink:   uplink,
		downlink: downlink,
		upCloser: upCloser,
		dnCloser: dnCloser,
		quicSess: quicSession,
		quicFlow: quicFlow,
	}, nil
}
