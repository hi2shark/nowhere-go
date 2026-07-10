package wire

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

func MakeAuthFrame(key string, spec *EffectiveSpec) (frame []byte, sessionID SessionID, err error) {
	if spec == nil {
		return nil, SessionID{}, errors.New("nowhere: nil effective spec")
	}
	nonce := make([]byte, authNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, SessionID{}, fmt.Errorf("nowhere: generate auth nonce: %w", err)
	}
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, SessionID{}, fmt.Errorf("nowhere: generate auth session id: %w", err)
	}
	return assembleAuthFrame(key, spec, nonce, sessionID), sessionID, nil
}

func MakeAuthFrameWithSession(key string, spec *EffectiveSpec, sessionID SessionID) ([]byte, error) {
	if spec == nil {
		return nil, errors.New("nowhere: nil effective spec")
	}
	nonce := make([]byte, authNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nowhere: generate auth nonce: %w", err)
	}
	return assembleAuthFrame(key, spec, nonce, sessionID), nil
}

// MakeAuthFrameWithNonce pins nonce and session id for conformance-vector tests.
func MakeAuthFrameWithNonce(key string, spec *EffectiveSpec, nonce []byte, sessionID SessionID) ([]byte, error) {
	if spec == nil {
		return nil, errors.New("nowhere: nil effective spec")
	}
	if len(nonce) != authNonceLength {
		return nil, fmt.Errorf("nowhere: auth nonce must be %d bytes", authNonceLength)
	}
	return assembleAuthFrame(key, spec, nonce, sessionID), nil
}

func assembleAuthFrame(key string, spec *EffectiveSpec, nonce []byte, sessionID SessionID) []byte {
	padding := authPaddingBytes(spec, nonce)

	authKey := sha256.Sum256([]byte(key))
	tagMsg := make([]byte, 0,
		len(spec.AuthInfo)+len(spec.AuthContext)+len(nonce)+1+len(padding)+SessionIDLen)
	tagMsg = append(tagMsg, spec.AuthInfo...)
	tagMsg = append(tagMsg, spec.AuthContext...)
	tagMsg = append(tagMsg, nonce...)
	tagMsg = append(tagMsg, spec.AuthPaddingLen)
	tagMsg = append(tagMsg, padding...)
	tagMsg = append(tagMsg, sessionID[:]...)
	tag := hmacSHA256(authKey[:], tagMsg)

	paddingBlock := make([]byte, 1+len(padding))
	paddingBlock[0] = spec.AuthPaddingLen
	copy(paddingBlock[1:], padding)

	frame := make([]byte, 0, authFrameLen(spec))
	for _, element := range spec.AuthFrameOrder {
		switch element {
		case AuthMagic:
			frame = append(frame, spec.AuthMagic...)
		case AuthNonce:
			frame = append(frame, nonce...)
		case AuthPadding:
			frame = append(frame, paddingBlock...)
		case AuthTag:
			frame = append(frame, tag...)
		}
	}
	frame = append(frame, sessionID[:]...)
	return frame
}

func authFrameLen(spec *EffectiveSpec) int {
	return authMagicLength + authNonceLength + 1 + int(spec.AuthPaddingLen) + authTagLength + SessionIDLen
}

func authPaddingBytes(spec *EffectiveSpec, nonce []byte) []byte {
	info := make([]byte, 0, len(authPaddingBytesLabel)+len(nonce)+1)
	info = append(info, authPaddingBytesLabel...)
	info = append(info, nonce...)
	info = append(info, spec.AuthPaddingLen)
	return hkdfExpand(spec.AuthPaddingKey, info, int(spec.AuthPaddingLen))
}

// ValidateAuthFrame checks length, fields, and HMAC tag in constant time.
func ValidateAuthFrame(msg []byte, key string, spec *EffectiveSpec) (SessionID, error) {
	var sessionID SessionID
	if spec == nil {
		return sessionID, errors.New("nowhere: nil effective spec")
	}
	if len(msg) != authFrameLen(spec) {
		return sessionID, ErrInvalidFrame
	}

	offset := 0
	var magic, nonce, paddingBlock, tag []byte
	for _, element := range spec.AuthFrameOrder {
		var fieldLen int
		switch element {
		case AuthMagic:
			fieldLen = authMagicLength
			magic = msg[offset : offset+fieldLen]
		case AuthNonce:
			fieldLen = authNonceLength
			nonce = msg[offset : offset+fieldLen]
		case AuthPadding:
			fieldLen = 1 + int(spec.AuthPaddingLen)
			paddingBlock = msg[offset : offset+fieldLen]
		case AuthTag:
			fieldLen = authTagLength
			tag = msg[offset : offset+fieldLen]
		}
		offset += fieldLen
	}

	copy(sessionID[:], msg[offset:offset+SessionIDLen])
	padding := paddingBlock[1:]
	expectedPadding := authPaddingBytes(spec, nonce)

	authKey := sha256.Sum256([]byte(key))
	tagMsg := make([]byte, 0,
		len(spec.AuthInfo)+len(spec.AuthContext)+len(nonce)+1+len(padding)+SessionIDLen)
	tagMsg = append(tagMsg, spec.AuthInfo...)
	tagMsg = append(tagMsg, spec.AuthContext...)
	tagMsg = append(tagMsg, nonce...)
	tagMsg = append(tagMsg, spec.AuthPaddingLen)
	tagMsg = append(tagMsg, padding...)
	tagMsg = append(tagMsg, sessionID[:]...)
	expectedTag := hmacSHA256(authKey[:], tagMsg)

	var diff byte
	diff |= constantTimeDiff(magic, spec.AuthMagic)
	diff |= paddingBlock[0] ^ spec.AuthPaddingLen
	diff |= constantTimeDiff(padding, expectedPadding)
	diff |= constantTimeDiff(tag, expectedTag)
	if diff != 0 {
		return SessionID{}, ErrInvalidFrame
	}
	return sessionID, nil
}

func ReadAuthFrame(r io.Reader, key string, spec *EffectiveSpec) (SessionID, error) {
	if spec == nil {
		return SessionID{}, ErrInvalidFrame
	}
	buf := make([]byte, authFrameLen(spec))
	if _, err := io.ReadFull(r, buf); err != nil {
		return SessionID{}, err
	}
	return ValidateAuthFrame(buf, key, spec)
}

// DecodeTCPRequest reads a TCP request frame in the effective spec field order.
