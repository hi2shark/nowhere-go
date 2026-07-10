package quic

import "context"

// Session is one authenticated QUIC connection used by asymmetric UDP flows.
// Host backends typically map this to a single multiplexed QUIC connection.
type Session interface {
	EnsureReady(ctx context.Context) error
	RegisterUDPAsymmetricFlow(ctx context.Context, dest string, flowID uint64) (UDPFlow, error)
	ReleaseUDPAsymmetricFlow(flowID uint64)
	SendDatagram(frame []byte) error
}
