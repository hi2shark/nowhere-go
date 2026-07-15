package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

// Flow envelope prepended to every Nowhere 1.4 logical flow.
const (
	FlowFrameMagic   byte = 0xf1
	FlowFrameVersion byte = 1
	FlowHeaderLen         = 14
)

type FlowRole uint8

const (
	FlowRoleOpen   FlowRole = 1 // uplink: client->target
	FlowRoleAttach FlowRole = 2 // downlink: target->client
	FlowRoleDuplex FlowRole = 3 // one carrier owns both directions
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
	if err := validateFlowHeader(h); err != nil {
		return [FlowHeaderLen]byte{}, err
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
	header := FlowHeader{
		Role:     FlowRole(buf[2]),
		FlowID:   binary.BigEndian.Uint64(buf[3:11]),
		Kind:     FlowKind(buf[11]),
		Uplink:   Carrier(buf[12]),
		Downlink: Carrier(buf[13]),
	}
	if err := validateFlowHeader(header); err != nil {
		return FlowHeader{}, ErrInvalidFlowHeader
	}
	return header, nil
}

// EncodeFlowSetup writes the common header and, except for Attach, one target request.
func EncodeFlowSetup(header FlowHeader, target string, spec *EffectiveSpec) ([]byte, error) {
	encodedHeader, err := WriteFlowHeader(header)
	if err != nil {
		return nil, err
	}
	setup := append([]byte(nil), encodedHeader[:]...)
	if header.Role == FlowRoleAttach {
		return setup, nil
	}
	request, err := EncodeTCPRequest(target, spec)
	if err != nil {
		return nil, err
	}
	return append(setup, request...), nil
}

func validateFlowHeader(header FlowHeader) error {
	if header.FlowID == 0 {
		return errors.New("nowhere: zero flow id")
	}
	if header.Role != FlowRoleOpen && header.Role != FlowRoleAttach && header.Role != FlowRoleDuplex {
		return errors.New("nowhere: invalid flow role")
	}
	if header.Kind != FlowKindTCP && header.Kind != FlowKindUDP {
		return errors.New("nowhere: invalid flow kind")
	}
	if header.Uplink != CarrierTCP && header.Uplink != CarrierUDP {
		return errors.New("nowhere: invalid uplink carrier")
	}
	if header.Downlink != CarrierTCP && header.Downlink != CarrierUDP {
		return errors.New("nowhere: invalid downlink carrier")
	}
	if header.Role == FlowRoleDuplex && header.Uplink != header.Downlink {
		return errors.New("nowhere: duplex carriers must match")
	}
	if header.Role != FlowRoleDuplex && header.Uplink == header.Downlink {
		return errors.New("nowhere: split carriers must differ")
	}
	return nil
}
