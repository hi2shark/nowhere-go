package wire

// Auth / TCP / UDP frame element orders are derived from the effective spec seed.

type AuthFrameElement uint8

const (
	AuthMagic AuthFrameElement = iota
	AuthNonce
	AuthPadding
	AuthTag
)

type TcpFrameElement uint8

const (
	TcpVersion TcpFrameElement = iota
	TcpTarget
	TcpPadding
)

type UdpFrameElement uint8

const (
	UdpVersion UdpFrameElement = iota
	UdpType
	UdpFlowID
	UdpTarget
)

const (
	UDPTypeRequest  uint8 = 1
	UDPTypeResponse uint8 = 2
	UDPTypeClose    uint8 = 3
)

// Fisher-Yates shuffle; rotate left once if unchanged.
func authFrameOrderFromSeed(seed []byte) []AuthFrameElement {
	canonical := []AuthFrameElement{AuthMagic, AuthNonce, AuthPadding, AuthTag}
	order := make([]AuthFrameElement, len(canonical))
	copy(order, canonical)
	for i := len(order) - 1; i >= 1; i-- {
		seedIndex := len(order) - 1 - i
		var seedByte byte
		if seedIndex < len(seed) {
			seedByte = seed[seedIndex]
		}
		j := int(seedByte) % (i + 1)
		order[i], order[j] = order[j], order[i]
	}
	if equalAuthOrder(order, canonical) {
		first := order[0]
		copy(order, order[1:])
		order[len(order)-1] = first
	}
	return order
}

// TCP uses seed offset 0; UDP uses offset 1.
func frameLayoutFromSeed(seed []byte) (tcp []TcpFrameElement, udp []UdpFrameElement) {
	tcpCanonical := []TcpFrameElement{TcpVersion, TcpTarget, TcpPadding}
	tcp = make([]TcpFrameElement, len(tcpCanonical))
	copy(tcp, tcpCanonical)
	for i := len(tcp) - 1; i >= 1; i-- {
		seedIndex := len(tcp) - 1 - i
		var seedByte byte
		if seedIndex < len(seed) {
			seedByte = seed[seedIndex]
		}
		j := int(seedByte) % (i + 1)
		tcp[i], tcp[j] = tcp[j], tcp[i]
	}

	udpCanonical := []UdpFrameElement{UdpVersion, UdpType, UdpFlowID, UdpTarget}
	udp = make([]UdpFrameElement, len(udpCanonical))
	copy(udp, udpCanonical)
	for i := len(udp) - 1; i >= 1; i-- {
		seedIndex := len(udp) - i
		var seedByte byte
		if seedIndex < len(seed) {
			seedByte = seed[seedIndex]
		}
		j := int(seedByte) % (i + 1)
		udp[i], udp[j] = udp[j], udp[i]
	}
	return tcp, udp
}

func equalAuthOrder(a, b []AuthFrameElement) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
