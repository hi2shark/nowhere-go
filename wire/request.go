package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

func EncodeTCPRequest(target string, spec *EffectiveSpec) ([]byte, error) {
	if spec == nil {
		return nil, errors.New("nowhere: nil effective spec")
	}
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	targetBytes := []byte(target)
	padding := tcpRequestPaddingBytes(spec, target)

	frame := make([]byte, 0, 1+2+len(targetBytes)+1+len(padding))
	for _, element := range spec.tcpFrameOrder {
		switch element {
		case TcpVersion:
			frame = append(frame, ProxyFrameVersion)
		case TcpTarget:
			frame = append(frame, byte(len(targetBytes)>>8), byte(len(targetBytes)))
			frame = append(frame, targetBytes...)
		case TcpPadding:
			frame = append(frame, spec.tcpPaddingLen)
			frame = append(frame, padding...)
		}
	}
	return frame, nil
}

func tcpRequestPaddingBytes(spec *EffectiveSpec, target string) []byte {
	info := make([]byte, 0, len(tcpPaddingBytesLabel)+len(target)+1)
	info = append(info, tcpPaddingBytesLabel...)
	info = append(info, target...)
	info = append(info, spec.tcpPaddingLen)
	return hkdfExpand(spec.tcpPaddingKey, info, int(spec.tcpPaddingLen))
}

func DecodeTCPRequest(r io.Reader, spec *EffectiveSpec) (string, error) {
	if spec == nil {
		return "", ErrInvalidFrame
	}
	var target string
	var padding []byte
	haveTarget, havePadding := false, false

	for _, element := range spec.tcpFrameOrder {
		switch element {
		case TcpVersion:
			var version [1]byte
			if _, err := io.ReadFull(r, version[:]); err != nil {
				return "", err
			}
			if version[0] != ProxyFrameVersion {
				return "", ErrUnsupportedVersion
			}
		case TcpTarget:
			var lenBuf [2]byte
			if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
				return "", err
			}
			targetLen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if targetLen == 0 || targetLen > maxTargetLength {
				return "", ErrInvalidTarget
			}
			raw := make([]byte, targetLen)
			if _, err := io.ReadFull(r, raw); err != nil {
				return "", err
			}
			target = string(raw)
			if err := validateTarget(target); err != nil {
				return "", err
			}
			haveTarget = true
			if havePadding {
				if err := validateTCPPadding(spec, target, padding); err != nil {
					return "", err
				}
			}
		case TcpPadding:
			var lenBuf [1]byte
			if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
				return "", err
			}
			if lenBuf[0] != spec.tcpPaddingLen {
				return "", ErrInvalidFrame
			}
			padding = make([]byte, int(spec.tcpPaddingLen))
			if len(padding) > 0 {
				if _, err := io.ReadFull(r, padding); err != nil {
					return "", err
				}
			}
			havePadding = true
			if haveTarget {
				if err := validateTCPPadding(spec, target, padding); err != nil {
					return "", err
				}
			}
		}
	}
	if !haveTarget || !havePadding {
		return "", ErrInvalidFrame
	}
	return target, nil
}

func validateTCPPadding(spec *EffectiveSpec, target string, padding []byte) error {
	expected := tcpRequestPaddingBytes(spec, target)
	if constantTimeDiff(padding, expected) != 0 {
		return ErrInvalidFrame
	}
	return nil
}

// validateTarget verifies a non-empty UTF-8 host:port target.
func validateTarget(target string) error {
	if len(target) == 0 || len(target) > maxTargetLength {
		return fmt.Errorf("%w: length %d", ErrInvalidTarget, len(target))
	}
	if !utf8.ValidString(target) {
		return fmt.Errorf("%w: invalid UTF-8", ErrInvalidTarget)
	}
	port, err := splitHostPort(target)
	if err != nil {
		return err
	}
	if port == "" {
		return fmt.Errorf("%w: empty port", ErrInvalidTarget)
	}
	return nil
}

func splitHostPort(target string) (port string, err error) {
	if len(target) == 0 {
		return "", fmt.Errorf("%w: empty address", ErrInvalidTarget)
	}
	if target[0] == '[' {
		end := -1
		for i := 1; i < len(target); i++ {
			if target[i] == ']' {
				end = i
				break
			}
		}
		if end < 0 {
			return "", fmt.Errorf("%w: missing ']' in address", ErrInvalidTarget)
		}
		rest := target[end+1:]
		if len(rest) == 0 || rest[0] != ':' {
			return "", fmt.Errorf("%w: missing port in address", ErrInvalidTarget)
		}
		return rest[1:], nil
	}
	colons := 0
	colonIdx := -1
	for i := 0; i < len(target); i++ {
		if target[i] == ':' {
			colons++
			colonIdx = i
		}
	}
	if colons != 1 || colonIdx < 0 {
		return "", fmt.Errorf("%w: too many colons in address", ErrInvalidTarget)
	}
	return target[colonIdx+1:], nil
}
