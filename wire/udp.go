package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	UDPFrameMagic    = "NOWU"
	UDPMaxPacketSize = 65535
)

const (
	UDPFrameData  UDPFrameType = 1
	UDPFrameClose UDPFrameType = 2
)

type UDPFrameType uint8

type UDPFragment struct {
	PacketID      uint32
	FragmentID    uint8
	FragmentCount uint8
	TotalLen      uint16
	Payload       []byte
}

type UDPFrame struct {
	Type     UDPFrameType
	FlowID   uint64
	Fragment UDPFragment
}

const (
	udpControlHeaderLen  = 4 + 1 + 8
	udpFragmentHeaderLen = 4 + 1 + 1 + 2
	udpDataHeaderLen     = udpControlHeaderLen + udpFragmentHeaderLen
)

var (
	ErrInvalidUDPFrame = errors.New("nowhere: invalid udp frame")
)

// EncodeUDPDataFragments splits a UDP payload into DATAGRAM-sized NOWU DATA frames.
func EncodeUDPDataFragments(flowID uint64, packetID uint32, payload []byte, maxDatagramSize int) ([][]byte, error) {
	if flowID == 0 {
		return nil, errors.New("nowhere: zero flow id")
	}
	if packetID == 0 {
		return nil, errors.New("nowhere: zero packet id")
	}
	if len(payload) > UDPMaxPacketSize {
		return nil, fmt.Errorf("nowhere: udp payload %d exceeds max %d", len(payload), UDPMaxPacketSize)
	}
	if maxDatagramSize < udpDataHeaderLen {
		return nil, fmt.Errorf("nowhere: datagram size %d smaller than data header %d", maxDatagramSize, udpDataHeaderLen)
	}
	maxPayload := maxDatagramSize - udpDataHeaderLen
	if len(payload) == 0 {
		frame := make([]byte, 0, udpDataHeaderLen)
		writeUDPBaseHeader(&frame, uint8(UDPFrameData), flowID)
		writeUDPFragmentHeader(&frame, packetID, 0, 1, 0)
		return [][]byte{frame}, nil
	}
	if maxPayload == 0 {
		return nil, errors.New("nowhere: no datagram payload capacity")
	}
	fragmentCount := (len(payload) + maxPayload - 1) / maxPayload
	if fragmentCount > 255 {
		return nil, fmt.Errorf("nowhere: too many udp fragments: %d", fragmentCount)
	}
	totalLen := uint16(len(payload))
	frames := make([][]byte, 0, fragmentCount)
	for fragmentID := 0; fragmentID < fragmentCount; fragmentID++ {
		start := fragmentID * maxPayload
		end := len(payload)
		if next := start + maxPayload; next < end {
			end = next
		}
		fragmentPayload := payload[start:end]
		frame := make([]byte, 0, udpDataHeaderLen+len(fragmentPayload))
		writeUDPBaseHeader(&frame, uint8(UDPFrameData), flowID)
		writeUDPFragmentHeader(&frame, packetID, uint8(fragmentID), uint8(fragmentCount), totalLen)
		frame = append(frame, fragmentPayload...)
		frames = append(frames, frame)
	}
	return frames, nil
}

// EncodeUDPClose encodes a NOWU CLOSE frame.
func EncodeUDPClose(flowID uint64) ([]byte, error) {
	if flowID == 0 {
		return nil, errors.New("nowhere: zero flow id")
	}
	frame := make([]byte, 0, udpControlHeaderLen)
	writeUDPBaseHeader(&frame, uint8(UDPFrameClose), flowID)
	return frame, nil
}

// DecodeUDPFrame decodes one fixed NOWU frame.
func DecodeUDPFrame(buf []byte) (UDPFrame, error) {
	if len(buf) < udpControlHeaderLen || string(buf[:4]) != UDPFrameMagic {
		return UDPFrame{}, ErrInvalidUDPFrame
	}
	frameType := UDPFrameType(buf[4])
	flowID := binary.BigEndian.Uint64(buf[5:udpControlHeaderLen])
	if flowID == 0 {
		return UDPFrame{}, ErrInvalidUDPFrame
	}
	switch frameType {
	case UDPFrameClose:
		if len(buf) != udpControlHeaderLen {
			return UDPFrame{}, ErrInvalidUDPFrame
		}
		return UDPFrame{Type: UDPFrameClose, FlowID: flowID}, nil
	case UDPFrameData:
		fragment, err := decodeUDPFragment(buf, udpControlHeaderLen)
		if err != nil {
			return UDPFrame{}, err
		}
		return UDPFrame{Type: UDPFrameData, FlowID: flowID, Fragment: fragment}, nil
	default:
		return UDPFrame{}, ErrInvalidUDPFrame
	}
}

func decodeUDPFragment(buf []byte, offset int) (UDPFragment, error) {
	payloadOffset := offset + udpFragmentHeaderLen
	if len(buf) < payloadOffset {
		return UDPFragment{}, ErrInvalidUDPFrame
	}
	packetID := binary.BigEndian.Uint32(buf[offset : offset+4])
	if packetID == 0 {
		return UDPFragment{}, ErrInvalidUDPFrame
	}
	fragmentID := buf[offset+4]
	fragmentCount := buf[offset+5]
	totalLen := binary.BigEndian.Uint16(buf[offset+6 : offset+8])
	payload := buf[payloadOffset:]
	if fragmentCount == 0 || fragmentID >= fragmentCount {
		return UDPFragment{}, ErrInvalidUDPFrame
	}
	if len(payload) > int(totalLen) {
		return UDPFragment{}, ErrInvalidUDPFrame
	}
	if totalLen == 0 {
		if fragmentCount != 1 || fragmentID != 0 || len(payload) != 0 {
			return UDPFragment{}, ErrInvalidUDPFrame
		}
	} else {
		if len(payload) == 0 {
			return UDPFragment{}, ErrInvalidUDPFrame
		}
		if fragmentCount == 1 && len(payload) != int(totalLen) {
			return UDPFragment{}, ErrInvalidUDPFrame
		}
	}
	return UDPFragment{
		PacketID:      packetID,
		FragmentID:    fragmentID,
		FragmentCount: fragmentCount,
		TotalLen:      totalLen,
		Payload:       payload,
	}, nil
}

func writeUDPBaseHeader(out *[]byte, frameType uint8, flowID uint64) {
	*out = append(*out, UDPFrameMagic...)
	*out = append(*out, frameType)
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], flowID)
	*out = append(*out, id[:]...)
}

func writeUDPFragmentHeader(out *[]byte, packetID uint32, fragmentID, fragmentCount uint8, totalLen uint16) {
	var pid [4]byte
	binary.BigEndian.PutUint32(pid[:], packetID)
	*out = append(*out, pid[:]...)
	*out = append(*out, fragmentID, fragmentCount)
	var tl [2]byte
	binary.BigEndian.PutUint16(tl[:], totalLen)
	*out = append(*out, tl[:]...)
}
