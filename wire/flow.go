package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

// Asymmetric-flow envelope prepended to request frames when up != down.
const (
	FlowFrameMagic   byte = 0xf1 // distinguishes envelope from ordinary request (version byte)
	FlowFrameVersion byte = 1
	FlowHeaderLen         = 14
)

type FlowRole uint8

const (
	FlowRoleOpen   FlowRole = 1 // uplink: client->target
	FlowRoleAttach FlowRole = 2 // downlink: target->client
)

type FlowKind uint8

const (
	FlowKindTCP FlowKind = 1
	FlowKindUDP FlowKind = 2
)

type Carrier uint8

const (
	CarrierTCP Carrier = 1
	CarrierUDP Carrier = 2
)

type FlowHeader struct {
	Role     FlowRole
	FlowID   uint64
	Kind     FlowKind
	Uplink   Carrier
	Downlink Carrier
}

var ErrInvalidFlowHeader = errors.New("nowhere: invalid flow header")

func WriteFlowHeader(h FlowHeader) ([FlowHeaderLen]byte, error) {
	if h.FlowID == 0 {
		return [FlowHeaderLen]byte{}, errors.New("nowhere: zero flow id")
	}
	if h.Role != FlowRoleOpen && h.Role != FlowRoleAttach {
		return [FlowHeaderLen]byte{}, errors.New("nowhere: invalid flow role")
	}
	if h.Kind != FlowKindTCP && h.Kind != FlowKindUDP {
		return [FlowHeaderLen]byte{}, errors.New("nowhere: invalid flow kind")
	}
	if h.Uplink != CarrierTCP && h.Uplink != CarrierUDP {
		return [FlowHeaderLen]byte{}, errors.New("nowhere: invalid uplink carrier")
	}
	if h.Downlink != CarrierTCP && h.Downlink != CarrierUDP {
		return [FlowHeaderLen]byte{}, errors.New("nowhere: invalid downlink carrier")
	}
	// Symmetric carriers must not use the envelope.
	if h.Uplink == h.Downlink {
		return [FlowHeaderLen]byte{}, errors.New("nowhere: uplink must differ from downlink")
	}
	var out [FlowHeaderLen]byte
	out[0] = FlowFrameMagic
	out[1] = FlowFrameVersion
	out[2] = byte(h.Role)
	binary.BigEndian.PutUint64(out[3:11], h.FlowID)
	out[11] = byte(h.Kind)
	out[12] = byte(h.Uplink)
	out[13] = byte(h.Downlink)
	return out, nil
}

func ReadFlowHeader(r io.Reader) (FlowHeader, error) {
	var buf [FlowHeaderLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return FlowHeader{}, err
	}
	if buf[0] != FlowFrameMagic || buf[1] != FlowFrameVersion {
		return FlowHeader{}, ErrInvalidFlowHeader
	}
	role := FlowRole(buf[2])
	if role != FlowRoleOpen && role != FlowRoleAttach {
		return FlowHeader{}, ErrInvalidFlowHeader
	}
	flowID := binary.BigEndian.Uint64(buf[3:11])
	if flowID == 0 {
		return FlowHeader{}, ErrInvalidFlowHeader
	}
	kind := FlowKind(buf[11])
	if kind != FlowKindTCP && kind != FlowKindUDP {
		return FlowHeader{}, ErrInvalidFlowHeader
	}
	uplink := Carrier(buf[12])
	downlink := Carrier(buf[13])
	if uplink != CarrierTCP && uplink != CarrierUDP {
		return FlowHeader{}, ErrInvalidFlowHeader
	}
	if downlink != CarrierTCP && downlink != CarrierUDP {
		return FlowHeader{}, ErrInvalidFlowHeader
	}
	if uplink == downlink {
		return FlowHeader{}, ErrInvalidFlowHeader
	}
	return FlowHeader{
		Role:     role,
		FlowID:   flowID,
		Kind:     kind,
		Uplink:   uplink,
		Downlink: downlink,
	}, nil
}
