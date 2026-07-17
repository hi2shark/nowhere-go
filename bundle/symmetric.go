package bundle

import (
	"context"
	"errors"
	"net"

	"github.com/hi2shark/nowhere-go/wire"
)

// OpenTCP opens a TCP logical flow using the configured carrier matrix.
func (b *CarrierBundle) OpenTCP(ctx context.Context, target wire.Target) (net.Conn, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if b.cfg.up != b.cfg.down {
		return b.openAsymmetricTCP(ctx, target)
	}
	switch b.cfg.up {
	case wire.CarrierTLSTCP:
		return b.openSymmetricTCPTCP(ctx, target)
	case wire.CarrierQUIC:
		return b.openSymmetricUDPQUIC(ctx, target)
	default:
		return nil, errors.New("nowhere: invalid carrier")
	}
}

// OpenUDP opens a UDP logical flow using the configured carrier matrix.
func (b *CarrierBundle) OpenUDP(ctx context.Context, target wire.Target) (net.PacketConn, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if b.cfg.up != b.cfg.down {
		return b.openAsymmetricUDP(ctx, target)
	}
	switch b.cfg.up {
	case wire.CarrierTLSTCP:
		return b.openSymmetricTCPUDP(ctx, target)
	case wire.CarrierQUIC:
		return b.openSymmetricUDPQUICUDP(ctx, target)
	default:
		return nil, errors.New("nowhere: invalid carrier")
	}
}

func (b *CarrierBundle) openSymmetricTCPTCP(ctx context.Context, target wire.Target) (net.Conn, error) {
	setup, err := b.newDuplexSetup(wire.FlowKindTCP, target)
	if err != nil {
		return nil, err
	}
	half, err := b.prepareTCPHalf(ctx, target, setup.header)
	if err != nil {
		return nil, fmtError("prepare tcp duplex", err)
	}
	return commitTCPFlow(half)
}

func (b *CarrierBundle) openSymmetricUDPQUIC(ctx context.Context, target wire.Target) (net.Conn, error) {
	setup, err := b.newDuplexSetup(wire.FlowKindTCP, target)
	if err != nil {
		return nil, err
	}
	return b.openQUICDuplexStream(ctx, setup)
}

func (b *CarrierBundle) openSymmetricTCPUDP(ctx context.Context, target wire.Target) (net.PacketConn, error) {
	setup, err := b.newDuplexSetup(wire.FlowKindUDP, target)
	if err != nil {
		return nil, err
	}
	half, err := b.prepareTCPHalf(ctx, target, setup.header)
	if err != nil {
		return nil, fmtError("prepare tcp uot duplex", err)
	}
	conn, err := half.Commit()
	if err != nil {
		return nil, err
	}
	if err := readSetupResult(conn); err != nil {
		_ = conn.Close()
		return nil, fmtError("read tcp uot setup result", err)
	}
	return newUOTPacketConn(conn, targetToAddr(target)), nil
}

func (b *CarrierBundle) openSymmetricUDPQUICUDP(ctx context.Context, target wire.Target) (net.PacketConn, error) {
	setup, err := b.newDuplexSetup(wire.FlowKindUDP, target)
	if err != nil {
		return nil, err
	}
	prep, err := b.prepareQUICStream(ctx, setup.header.FlowID)
	if err != nil {
		return nil, fmtError("prepare quic udp duplex", err)
	}
	setupBytes, err := setup.bytes()
	if err != nil {
		_ = prep.Close()
		return nil, fmtError("encode udp duplex setup", err)
	}
	conn, err := commitQUICFlow(ctx, prep, setupBytes)
	if err != nil {
		_ = prep.Close()
		return nil, err
	}
	return newQUICPacketConn(prep, conn, target), nil
}

func (b *CarrierBundle) openQUICDuplexStream(ctx context.Context, setup flowSetup) (net.Conn, error) {
	prep, err := b.prepareQUICStream(ctx, setup.header.FlowID)
	if err != nil {
		return nil, fmtError("prepare quic duplex", err)
	}
	setupBytes, err := setup.bytes()
	if err != nil {
		_ = prep.Close()
		return nil, fmtError("encode duplex setup", err)
	}
	conn, err := commitQUICHalf(ctx, prep, setupBytes, false)
	if err != nil {
		_ = prep.Close()
		return nil, err
	}
	if err := readSetupResult(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
