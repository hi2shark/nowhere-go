package wire

import (
	"encoding/binary"
	"io"
)

func EncodeUOTSetupTarget(target string) ([]byte, error) {
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	targetBytes := []byte(target)
	frame := make([]byte, 2+len(targetBytes))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(targetBytes)))
	copy(frame[2:], targetBytes)
	return frame, nil
}

func WriteUOTPacketFrame(payload []byte) ([]byte, error) {
	if len(payload) > 0xffff {
		return nil, ErrPaddingTooLarge
	}
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	return frame, nil
}

func ReadUOTPacketFrame(buf []byte) (payload []byte, consumed int, err error) {
	if len(buf) == 0 {
		return nil, 0, errUOTEOF
	}
	if len(buf) < 2 {
		return nil, 0, ErrInvalidFrame
	}
	length := int(binary.BigEndian.Uint16(buf[:2]))
	if len(buf) < 2+length {
		return nil, 0, ErrInvalidFrame
	}
	return buf[2 : 2+length], 2 + length, nil
}

func ReadUOTSetupTarget(r io.Reader) (string, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 || n > maxTargetLength {
		return "", ErrInvalidTarget
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return "", err
	}
	target := string(raw)
	if err := validateTarget(target); err != nil {
		return "", err
	}
	return target, nil
}
