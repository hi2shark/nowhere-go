package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type UDPMessage struct {
	Type    uint8
	FlowID  uint64
	Target  string
	Payload []byte
}

func EncodeUDPDatagram(frameType uint8, flowID uint64, target string, payload []byte, spec *EffectiveSpec) ([]byte, error) {
	if spec == nil {
		return nil, errors.New("nowhere: nil effective spec")
	}
	if !validUDPType(frameType) {
		return nil, fmt.Errorf("nowhere: invalid udp frame type %d", frameType)
	}
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	header, err := encodeUDPHeader(frameType, flowID, target, spec)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 0, len(header)+len(payload))
	frame = append(frame, header...)
	frame = append(frame, payload...)
	return frame, nil
}

func encodeUDPHeader(frameType uint8, flowID uint64, target string, spec *EffectiveSpec) ([]byte, error) {
	targetBytes := []byte(target)
	header := make([]byte, 0, datagramHeaderFixedLen+len(targetBytes))
	for _, element := range spec.udpFrameOrder {
		switch element {
		case UdpVersion:
			header = append(header, ProxyFrameVersion)
		case UdpType:
			header = append(header, frameType)
		case UdpFlowID:
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], flowID)
			header = append(header, buf[:]...)
		case UdpTarget:
			header = append(header, byte(len(targetBytes)>>8), byte(len(targetBytes)))
			header = append(header, targetBytes...)
		}
	}
	return header, nil
}

func UDPHeaderSize(target string) int {
	return datagramHeaderFixedLen + len(target)
}

func DecodeUDPDatagram(buf []byte, spec *EffectiveSpec) (*UDPMessage, error) {
	if spec == nil {
		return nil, errors.New("nowhere: nil effective spec")
	}
	if len(buf) < datagramHeaderFixedLen {
		return nil, ErrInvalidFrame
	}

	offset := 0
	var frameType byte
	var flowID uint64
	var target string
	haveType, haveFlowID, haveTarget := false, false, false

	for _, element := range spec.udpFrameOrder {
		switch element {
		case UdpVersion:
			if offset >= len(buf) {
				return nil, ErrInvalidFrame
			}
			if buf[offset] != ProxyFrameVersion {
				return nil, ErrUnsupportedVersion
			}
			offset++
		case UdpType:
			if offset >= len(buf) {
				return nil, ErrInvalidFrame
			}
			frameType = buf[offset]
			offset++
			haveType = true
		case UdpFlowID:
			if offset+8 > len(buf) {
				return nil, ErrInvalidFrame
			}
			flowID = binary.BigEndian.Uint64(buf[offset : offset+8])
			offset += 8
			haveFlowID = true
		case UdpTarget:
			if offset+2 > len(buf) {
				return nil, ErrInvalidFrame
			}
			targetLen := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
			offset += 2
			if targetLen == 0 || targetLen > maxTargetLength || offset+targetLen > len(buf) {
				return nil, ErrInvalidFrame
			}
			target = string(buf[offset : offset+targetLen])
			offset += targetLen
			if err := validateTarget(target); err != nil {
				return nil, err
			}
			haveTarget = true
		}
	}

	if !haveType || !validUDPType(frameType) {
		return nil, ErrInvalidFrame
	}
	if !haveFlowID || !haveTarget {
		return nil, ErrInvalidFrame
	}

	return &UDPMessage{
		Type:    frameType,
		FlowID:  flowID,
		Target:  target,
		Payload: buf[offset:],
	}, nil
}

func validUDPType(t uint8) bool {
	return t == UDPTypeRequest || t == UDPTypeResponse || t == UDPTypeClose
}

// Compact UDP data-plane types (0x11..0x14); fixed layout, not spec-derived order.
const (
	UDPTypeOpenData     uint8 = 0x11
	UDPTypeOpenAck      uint8 = 0x12
	UDPTypeData         uint8 = 0x13
	UDPTypeCompactClose uint8 = 0x14
)

const compactHeaderLen = 1 + 1 + 8

type CompactUDPFrame struct {
	Type     uint8
	FlowID   uint64
	Downlink Carrier
	Target   string
	Payload  []byte // aliases input buffer
}

func EncodeUDPOpenData(flowID uint64, downlink Carrier, target string, payload []byte) ([]byte, error) {
	if flowID == 0 {
		return nil, errors.New("nowhere: zero flow id")
	}
	if downlink != CarrierTCP && downlink != CarrierUDP {
		return nil, errors.New("nowhere: invalid downlink carrier")
	}
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	targetBytes := []byte(target)
	out := make([]byte, 0, compactHeaderLen+1+2+len(targetBytes)+len(payload))
	out = appendCompactHeader(out, UDPTypeOpenData, flowID)
	out = append(out, byte(downlink))
	out = append(out, byte(len(targetBytes)>>8), byte(len(targetBytes)))
	out = append(out, targetBytes...)
	out = append(out, payload...)
	return out, nil
}

func EncodeUDPCompact(frameType uint8, flowID uint64, payload []byte) ([]byte, error) {
	if flowID == 0 {
		return nil, errors.New("nowhere: zero flow id")
	}
	if frameType != UDPTypeOpenAck && frameType != UDPTypeData && frameType != UDPTypeCompactClose {
		return nil, fmt.Errorf("nowhere: invalid compact frame type %d", frameType)
	}
	if frameType != UDPTypeData && len(payload) != 0 {
		return nil, errors.New("nowhere: compact control frame must not carry payload")
	}
	out := make([]byte, 0, compactHeaderLen+len(payload))
	out = appendCompactHeader(out, frameType, flowID)
	out = append(out, payload...)
	return out, nil
}

func appendCompactHeader(out []byte, frameType uint8, flowID uint64) []byte {
	out = append(out, ProxyFrameVersion, frameType)
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], flowID)
	return append(out, id[:]...)
}

func DecodeUDPCompact(buf []byte) (CompactUDPFrame, error) {
	if len(buf) < compactHeaderLen || buf[0] != ProxyFrameVersion {
		return CompactUDPFrame{}, ErrInvalidFrame
	}
	frameType := buf[1]
	flowID := binary.BigEndian.Uint64(buf[2:10])
	if flowID == 0 {
		return CompactUDPFrame{}, ErrInvalidFrame
	}
	switch frameType {
	case UDPTypeOpenData:
		if len(buf) < compactHeaderLen+3 {
			return CompactUDPFrame{}, ErrInvalidFrame
		}
		downlink := Carrier(buf[10])
		if downlink != CarrierTCP && downlink != CarrierUDP {
			return CompactUDPFrame{}, ErrInvalidFrame
		}
		targetLen := int(binary.BigEndian.Uint16(buf[11:13]))
		targetEnd := compactHeaderLen + 3 + targetLen
		if targetLen == 0 || targetLen > maxTargetLength || targetEnd > len(buf) {
			return CompactUDPFrame{}, ErrInvalidFrame
		}
		target := string(buf[13:targetEnd])
		if err := validateTarget(target); err != nil {
			return CompactUDPFrame{}, err
		}
		return CompactUDPFrame{
			Type:     frameType,
			FlowID:   flowID,
			Downlink: downlink,
			Target:   target,
			Payload:  buf[targetEnd:],
		}, nil
	case UDPTypeOpenAck, UDPTypeCompactClose:
		if len(buf) != compactHeaderLen {
			return CompactUDPFrame{}, ErrInvalidFrame
		}
		return CompactUDPFrame{Type: frameType, FlowID: flowID}, nil
	case UDPTypeData:
		return CompactUDPFrame{Type: frameType, FlowID: flowID, Payload: buf[compactHeaderLen:]}, nil
	default:
		return CompactUDPFrame{}, ErrInvalidFrame
	}
}
