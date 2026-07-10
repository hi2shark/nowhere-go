package quic

import "net"

// UDPFlow is a DATAGRAM-backed UDP flow on an authenticated Session.
type UDPFlow interface {
	FlowID() uint64
	IsAcked() bool
	WaitReadFrom() (data []byte, put func(), addr net.Addr, err error)
	Shutdown(err error)
}
