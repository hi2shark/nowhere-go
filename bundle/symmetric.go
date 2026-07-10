package bundle

import (
	"context"
	"errors"
	"net"

	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

func (b *CarrierBundle) SymmetricOpenTCP(ctx context.Context, dest string) (net.Conn, error) {
	switch b.cfg.up {
	case wire.CarrierTCP:
		pool, err := b.tcpPool()
		if err != nil {
			return nil, err
		}
		if pool == nil {
			return nil, errors.New("nowhere: tcp carrier unavailable")
		}
		return pool.Acquire(ctx, dest, tcptls.TCPRelayTCP)
	default:
		client, err := b.quicClient()
		if err != nil {
			return nil, err
		}
		if client == nil {
			return nil, errors.New("nowhere: udp carrier unavailable")
		}
		return client.OpenTCP(ctx, dest)
	}
}

func (b *CarrierBundle) SymmetricOpenUDP(ctx context.Context, dest string) (net.PacketConn, net.Conn, error) {
	switch b.cfg.up {
	case wire.CarrierTCP:
		pool, err := b.tcpPool()
		if err != nil {
			return nil, nil, err
		}
		if pool == nil {
			return nil, nil, errors.New("nowhere: tcp carrier unavailable")
		}
		conn, err := pool.Acquire(ctx, dest, tcptls.TCPRelayUoT)
		if err != nil {
			return nil, nil, err
		}
		return nil, conn, nil
	default:
		client, err := b.quicClient()
		if err != nil {
			return nil, nil, err
		}
		if client == nil {
			return nil, nil, errors.New("nowhere: udp carrier unavailable")
		}
		pc, err := client.OpenUDP(ctx, dest)
		return pc, nil, err
	}
}
