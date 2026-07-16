package wire

import "net"

// HandshakedConn pairs a TLS-1.3 connection with the exporter derived from its
// handshake. It is the shared return type for both client (TLSDialer) and
// server (TLSHandshaker) handshakes, so neither carrier nor server needs to
// import the other.
type HandshakedConn struct {
	Conn     net.Conn
	Exporter TLSExporter
}
