// Package wire implements Nowhere v1 spec derivation, flow envelopes, and frame codecs.
// See Nowhere/docs/protocol.md.
package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	ProxyFrameVersion uint8 = 1
	DefaultALPN             = "now/1"
	DefaultSpec             = "auto"
	UOTMagicTarget          = "uot.nowhere.invalid:0" // switches TLS/TCP lane into UoT mode
	CloseErrCodeOK    uint64 = 0x100

	maxInputLength  = 255
	maxTargetLength = 512

	specIDLength         = 8
	authMagicLength      = 8
	authNonceLength      = 32
	authInfoLength       = 32
	authContextLength    = 32
	authTagLength        = 32
	authPaddingKeyLength = 32

	authPaddingLengthSeedLength = 2
	authPaddingLengthMax        = 255

	tcpPaddingKeyLength     = 32
	tcpPaddingLengthSeedLen = 1
	tcpPaddingLengthMax     = 64

	datagramHeaderFixedLen = 1 + 1 + 8 + 2

	// SessionIDLen is appended to every auth frame; one bundle shares one id for asymmetric pairing.
	SessionIDLen = 16
)

type SessionID [SessionIDLen]byte

var (
	specIDLabel            = []byte("spec id")
	authMagicLabel         = []byte("auth magic")
	authInfoLabel          = []byte("auth hmac info")
	authContextLabel       = []byte("auth context")
	authPaddingLengthLabel = []byte("auth padding length")
	authPaddingKeyLabel    = []byte("auth padding key")
	authPaddingBytesLabel  = []byte("auth padding bytes")
	tcpPaddingLengthLabel  = []byte("tcp request padding length")
	tcpPaddingKeyLabel     = []byte("tcp request padding key")
	tcpPaddingBytesLabel   = []byte("tcp request padding bytes")
	authFrameLayoutLabel   = []byte("auth frame layout")
	proxyFrameLayoutLabel  = []byte("proxy frame layout")
)


// EffectiveSpec is protocol material from spec/ALPN (independent of key shape).
type EffectiveSpec struct {
	EffectiveSpec   string
	EffectiveALPN   string
	DefaultALPN     string
	EffectiveSpecID string // base64url-no-pad diagnostic id, never transmitted

	AuthFrameOrder []AuthFrameElement
	AuthMagic      []byte
	AuthInfo       []byte
	AuthContext    []byte
	AuthPaddingLen uint8
	AuthPaddingKey []byte

	TcpFrameOrder []TcpFrameElement
	TcpPaddingLen uint8
	TcpPaddingKey []byte

	UdpFrameOrder []UdpFrameElement
}

// BuildEffectiveSpec derives v1 protocol material. The key is validated but does not affect shape.
func BuildEffectiveSpec(key, spec, alpn string) (*EffectiveSpec, error) {
	keyBytes := []byte(key)
	if len(keyBytes) == 0 {
		return nil, errors.New("nowhere: missing shared key")
	}
	if len(keyBytes) > maxInputLength {
		return nil, fmt.Errorf("nowhere: shared key exceeds %d bytes", maxInputLength)
	}

	effectiveSpec := spec
	if effectiveSpec != "" {
		if len([]byte(effectiveSpec)) > maxInputLength {
			return nil, fmt.Errorf("nowhere: spec exceeds %d bytes", maxInputLength)
		}
	} else {
		effectiveSpec = DefaultSpec
	}

	effectiveALPN := alpn
	if effectiveALPN != "" {
		if len([]byte(effectiveALPN)) > maxInputLength {
			return nil, fmt.Errorf("nowhere: alpn exceeds %d bytes", maxInputLength)
		}
	} else {
		effectiveALPN = DefaultALPN
	}

	specBytes := []byte(effectiveSpec)
	specSalt := sha256.Sum256(specBytes)
	specPRK := hkdfExtract(specSalt[:], specBytes)

	authMagic := hkdfExpand(specPRK, authMagicLabel, authMagicLength)
	authInfo := hkdfExpand(specPRK, authInfoLabel, authInfoLength)
	authContext := hkdfExpand(specPRK, authContextLabel, authContextLength)
	authPaddingKey := hkdfExpand(specPRK, authPaddingKeyLabel, authPaddingKeyLength)
	tcpPaddingKey := hkdfExpand(specPRK, tcpPaddingKeyLabel, tcpPaddingKeyLength)

	authPaddingLenSeed := hkdfExpand(specPRK, authPaddingLengthLabel, authPaddingLengthSeedLength)
	authPaddingLen := uint8(1 + (int(authPaddingLenSeed[0])<<8|int(authPaddingLenSeed[1]))%authPaddingLengthMax)

	tcpPaddingLenSeed := hkdfExpand(specPRK, tcpPaddingLengthLabel, tcpPaddingLengthSeedLen)
	tcpPaddingLen := tcpPaddingLenSeed[0] % tcpPaddingLengthMax

	authFrameOrder := authFrameOrderFromSeed(hkdfExpand(specPRK, authFrameLayoutLabel, 8))
	tcpFrameOrder, udpFrameOrder := frameLayoutFromSeed(hkdfExpand(specPRK, proxyFrameLayoutLabel, 8))

	specIDRaw := hkdfExpand(specPRK, specIDLabel, specIDLength)

	return &EffectiveSpec{
		EffectiveSpec:   effectiveSpec,
		EffectiveALPN:   effectiveALPN,
		DefaultALPN:     DefaultALPN,
		EffectiveSpecID: base64.RawURLEncoding.EncodeToString(specIDRaw),

		AuthFrameOrder: authFrameOrder,
		AuthMagic:      authMagic,
		AuthInfo:       authInfo,
		AuthContext:    authContext,
		AuthPaddingLen: authPaddingLen,
		AuthPaddingKey: authPaddingKey,

		TcpFrameOrder: tcpFrameOrder,
		TcpPaddingLen: tcpPaddingLen,
		TcpPaddingKey: tcpPaddingKey,

		UdpFrameOrder: udpFrameOrder,
	}, nil
}

func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var previous []byte
	var counter byte = 1
	for len(out) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(previous)
		mac.Write(info)
		mac.Write([]byte{counter})
		previous = mac.Sum(previous[:0])
		out = append(out, previous...)
		counter++
	}
	return out[:length]
}


func hmacSHA256(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// constantTimeDiff avoids timing oracles on tag/padding/magic comparisons.
func constantTimeDiff(a, b []byte) byte {
	var diff byte
	if len(a) != len(b) {
		diff = 1
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		diff |= a[i] ^ b[i]
	}
	return diff
}
