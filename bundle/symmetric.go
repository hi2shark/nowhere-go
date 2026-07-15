package bundle

import (
	"context"
	"errors"
	"net"

	"github.com/hi2shark/nowhere-go/wire"
)

// OpenTCP opens a TCP logical flow using the configured carrier matrix.
func (b *CarrierBundle) OpenTCP(ctx context.Context, dest string) (net.Conn, error) {
	if b.cfg.up != b.cfg.down {
		return b.openAsymmetricTCP(ctx, dest)
	}
	switch b.cfg.up {
	case wire.CarrierTCP:
		return b.openSymmetricTCPTCP(ctx, dest)
	case wire.CarrierUDP:
		return b.openSymmetricUDPQUIC(ctx, dest)
	default:
		return nil, errors.New("nowhere: invalid carrier")
	}
}

// OpenUDP opens a UDP logical flow using the configured carrier matrix.
func (b *CarrierBundle) OpenUDP(ctx context.Context, dest string) (net.PacketConn, error) {
	if b.cfg.up != b.cfg.down {
		return b.openAsymmetricUDP(ctx, dest)
	}
	switch b.cfg.up {
	case wire.CarrierTCP:
		return b.openSymmetricTCPUDP(ctx, dest)
	case wire.CarrierUDP:
		return b.openSymmetricUDPQUICUDP(ctx, dest)
	default:
		return nil, errors.New("nowhere: invalid carrier")
	}
}

func (b *CarrierBundle) openSymmetricTCPTCP(ctx context.Context, dest string) (net.Conn, error) {
	setup, err := b.newDuplexSetup(wire.FlowKindTCP, dest)
	if err != nil {
		return nil, err
	}
	half, err := b.prepareTCPHalf(ctx, dest, setup.header)
	if err != nil {
		return nil, fmtError("prepare tcp duplex", err)
	}
	return commitTCPFlow(half)
}

func (b *CarrierBundle) openSymmetricUDPQUIC(ctx context.Context, dest string) (net.Conn, error) {
	setup, err := b.newDuplexSetup(wire.FlowKindTCP, dest)
	if err != nil {
		return nil, err
	}
	return b.openQUICDuplexStream(ctx, setup)
}

func (b *CarrierBundle) openSymmetricTCPUDP(ctx context.Context, dest string) (net.PacketConn, error) {
	setup, err := b.newDuplexSetup(wire.FlowKindUDP, dest)
	if err != nil {
		return nil, err
	}
	half, err := b.prepareTCPHalf(ctx, dest, setup.header)
	if err != nil {
		return nil, fmtError("prepare tcp uot duplex", err)
	}
	conn, err := half.Commit()
	if err != nil {
		return nil, err
	}
	if err := readUOTSetupResult(conn); err != nil {
		_ = conn.Close()
		return nil, fmtError("read tcp uot setup result", err)
	}
	return newUOTPacketConn(conn, parseTargetAddr(dest)), nil
}

func (b *CarrierBundle) openSymmetricUDPQUICUDP(ctx context.Context, dest string) (net.PacketConn, error) {
	setup, err := b.newDuplexSetup(wire.FlowKindUDP, dest)
	if err != nil {
		return nil, err
	}
	prep, err := b.prepareQUICStream(ctx, setup.header.FlowID)
	if err != nil {
		return nil, fmtError("prepare quic udp duplex", err)
	}
	setupBytes, err := setup.bytes(b.cfg.tcp.Spec())
	if err != nil {
		_ = prep.Close()
		return nil, fmtError("encode udp duplex setup", err)
	}
	conn, err := commitQUICFlow(ctx, prep, setupBytes)
	if err != nil {
		_ = prep.Close()
		return nil, err
	}
	return newQUICPacketConn(prep, conn, dest), nil
}

func (b *CarrierBundle) openQUICDuplexStream(ctx context.Context, setup flowSetup) (net.Conn, error) {
	prep, err := b.prepareQUICStream(ctx, setup.header.FlowID)
	if err != nil {
		return nil, fmtError("prepare quic duplex", err)
	}
	setupBytes, err := setup.bytes(b.cfg.tcp.Spec())
	if err != nil {
		_ = prep.Close()
		return nil, fmtError("encode duplex setup", err)
	}
	conn, err := commitQUICHalf(ctx, prep, setupBytes, false)
	if err != nil {
		_ = prep.Close()
		return nil, err
	}
	if err := readFlowResult(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
