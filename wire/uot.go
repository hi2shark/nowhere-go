package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	UOTFrameData   UOTFrameKind = 1
	UOTFrameReady  UOTFrameKind = 2
	UOTFrameClose  UOTFrameKind = 3
	UOTFrameReject UOTFrameKind = 4
)

type UOTFrameKind uint8

type UOTFrame struct {
	Kind    UOTFrameKind
	Payload []byte
	Code    FlowErrorCode
}

var ErrInvalidUOTFrame = errors.New("nowhere: invalid uot frame")

// EncodeUOTFrame encodes one typed UoT frame.
func EncodeUOTFrame(frame UOTFrame) ([]byte, error) {
	frame = normalizeUOTFrame(frame)
	if err := validateUOTFrame(frame); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 3+len(frame.Payload))
	out = append(out, byte(frame.Kind))
	out = append(out, uint16Length(frame.Payload)...)
	out = append(out, frame.Payload...)
	return out, nil
}

// WriteUOTFrame writes one typed UoT frame to w.
func WriteUOTFrame(w io.Writer, frame UOTFrame) error {
	frame = normalizeUOTFrame(frame)
	if err := validateUOTFrame(frame); err != nil {
		return err
	}
	if _, err := w.Write([]byte{byte(frame.Kind)}); err != nil {
		return err
	}
	if _, err := w.Write(uint16Length(frame.Payload)); err != nil {
		return err
	}
	if len(frame.Payload) > 0 {
		if _, err := w.Write(frame.Payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadUOTFrame reads one typed UoT frame. Clean EOF before any frame returns io.EOF.
func ReadUOTFrame(r io.Reader) (UOTFrame, error) {
	var kindBuf [1]byte
	if _, err := io.ReadFull(r, kindBuf[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return UOTFrame{}, io.EOF
		}
		return UOTFrame{}, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return UOTFrame{}, io.ErrUnexpectedEOF
		}
		return UOTFrame{}, err
	}
	length := binary.BigEndian.Uint16(lenBuf[:])
	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			if errors.Is(err, io.EOF) {
				return UOTFrame{}, io.ErrUnexpectedEOF
			}
			return UOTFrame{}, err
		}
	}
	frame := UOTFrame{Kind: UOTFrameKind(kindBuf[0]), Payload: payload}
	if frame.Kind == UOTFrameReject && length == 1 {
		frame.Code = FlowErrorCode(payload[0])
	}
	frame = normalizeUOTFrame(frame)
	if err := validateUOTFrame(frame); err != nil {
		return UOTFrame{}, err
	}
	return frame, nil
}

func normalizeUOTFrame(frame UOTFrame) UOTFrame {
	if frame.Kind == UOTFrameReject && len(frame.Payload) == 0 && validFlowErrorCode(frame.Code) {
		frame.Payload = []byte{byte(frame.Code)}
	}
	return frame
}

func validateUOTFrame(frame UOTFrame) error {
	if len(frame.Payload) > UDPMaxPacketSize {
		return fmt.Errorf("nowhere: uot payload %d exceeds max %d", len(frame.Payload), UDPMaxPacketSize)
	}
	switch frame.Kind {
	case UOTFrameData:
	case UOTFrameReady, UOTFrameClose:
		if len(frame.Payload) != 0 {
			return ErrInvalidUOTFrame
		}
	case UOTFrameReject:
		if len(frame.Payload) != 1 {
			return ErrInvalidUOTFrame
		}
		if !validFlowErrorCode(FlowErrorCode(frame.Payload[0])) {
			return ErrInvalidUOTFrame
		}
	default:
		return ErrInvalidUOTFrame
	}
	return nil
}

func uint16Length(payload []byte) []byte {
	var out [2]byte
	binary.BigEndian.PutUint16(out[:], uint16(len(payload)))
	return out[:]
}
