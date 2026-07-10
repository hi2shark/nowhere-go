package tcptls

import (
	"net"
)

// wrapRelay promotes a consumed carrier to active_relay with diagnostic tracking.
func wrapRelay(conn net.Conn, ci *carrierInfo, flowID uint64, mode TCPRelayMode, target string) net.Conn {
	network := "tcp"
	if mode == TCPRelayUoT {
		network = "udp"
	}
	ci.transition(stateActiveRelay)
	ci.logger().Debugf("[Nowhere] [carrier] relay_start flow_id=%d carrier_id=%d network=%s target=%s",
		flowID, ci.id, network, target)
	return newTrackedConn(conn, ci, flowID, network, target)
}
