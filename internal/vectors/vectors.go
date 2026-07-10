// Package vectors loads and checks Nowhere harness JSON conformance vectors.
package vectors

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hi2shark/go-nowhere/wire"
)

// Dir resolves the vectors directory. Prefer GO_NOWHERE_VECTORS, then
// testdata/vectors relative to the module root (walk up from cwd), then the
// monorepo harness/vectors path when developing inside mihomo-nowhere.
func Dir() (string, error) {
	if env := strings.TrimSpace(os.Getenv("GO_NOWHERE_VECTORS")); env != "" {
		if st, err := os.Stat(env); err == nil && st.IsDir() {
			return env, nil
		}
		return "", fmt.Errorf("GO_NOWHERE_VECTORS=%q is not a directory", env)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		candidate := filepath.Join(dir, "testdata", "vectors")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate, nil
		}
		// Monorepo layout: <root>/go-nowhere + <root>/harness/vectors
		harness := filepath.Join(dir, "harness", "vectors")
		if st, err := os.Stat(harness); err == nil && st.IsDir() {
			return harness, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("vector directory not found (set GO_NOWHERE_VECTORS or run from module root)")
}

func decodeHex(s string) ([]byte, error) {
	clean := make([]byte, 0, len(s))
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			clean = append(clean, byte(r))
		}
	}
	return hex.DecodeString(string(clean))
}

type authFile struct {
	Cases []struct {
		ID            string `json:"id"`
		Key           string `json:"key"`
		Spec          string `json:"spec"`
		ALPN          string `json:"alpn"`
		NonceHex      string `json:"nonce_hex"`
		SessionIDHex  string `json:"session_id_hex"`
		FrameHex      string `json:"frame_hex"`
		FrameLen      int    `json:"frame_len"`
	} `json:"cases"`
}

type tcpFile struct {
	Cases []struct {
		ID       string `json:"id"`
		Key      string `json:"key"`
		Spec     string `json:"spec"`
		ALPN     string `json:"alpn"`
		Target   string `json:"target"`
		FrameHex string `json:"frame_hex"`
	} `json:"cases"`
}

type compactFile struct {
	Cases []struct {
		ID           string `json:"id"`
		TypeByte     uint8  `json:"type_byte"`
		FlowID       uint64 `json:"flow_id"`
		DownlinkByte uint8  `json:"downlink_byte"`
		Target       string `json:"target"`
		PayloadHex   string `json:"payload_hex"`
		FrameHex     string `json:"frame_hex"`
	} `json:"cases"`
}

type targetFile struct {
	Accept []struct {
		ID     string `json:"id"`
		Target string `json:"target"`
	} `json:"accept"`
	Reject []struct {
		ID     string `json:"id"`
		Target string `json:"target"`
	} `json:"reject"`
}

// CheckDir validates all known vector files under dir. Returns number of cases checked.
func CheckDir(dir string) (int, error) {
	n := 0
	if c, err := checkAuth(filepath.Join(dir, "auth.json")); err != nil {
		return n, err
	} else {
		n += c
	}
	if c, err := checkTCP(filepath.Join(dir, "tcp_request.json")); err != nil {
		return n, err
	} else {
		n += c
	}
	if c, err := checkCompact(filepath.Join(dir, "udp_compact.json")); err != nil {
		return n, err
	} else {
		n += c
	}
	if c, err := checkTarget(filepath.Join(dir, "target_addr.json")); err != nil {
		return n, err
	} else {
		n += c
	}
	return n, nil
}

func checkAuth(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f authFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	for _, tc := range f.Cases {
		spec, err := wire.BuildEffectiveSpec(tc.Key, tc.Spec, tc.ALPN)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", tc.ID, err)
		}
		nonce, err := decodeHex(tc.NonceHex)
		if err != nil {
			return 0, fmt.Errorf("%s: nonce: %w", tc.ID, err)
		}
		var sid wire.SessionID
		sidBytes, err := decodeHex(tc.SessionIDHex)
		if err != nil {
			return 0, fmt.Errorf("%s: session_id: %w", tc.ID, err)
		}
		if len(sidBytes) != wire.SessionIDLen {
			return 0, fmt.Errorf("%s: session_id length %d", tc.ID, len(sidBytes))
		}
		copy(sid[:], sidBytes)
		frame, err := wire.MakeAuthFrameWithNonce(tc.Key, spec, nonce, sid)
		if err != nil {
			return 0, fmt.Errorf("%s: encode: %w", tc.ID, err)
		}
		want, err := decodeHex(tc.FrameHex)
		if err != nil {
			return 0, fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
		}
		if tc.FrameLen > 0 && len(frame) != tc.FrameLen {
			return 0, fmt.Errorf("%s: frame len %d want %d", tc.ID, len(frame), tc.FrameLen)
		}
		if !bytes.Equal(frame, want) {
			return 0, fmt.Errorf("%s: auth frame mismatch\n got %x\nwant %x", tc.ID, frame, want)
		}
		gotID, err := wire.ValidateAuthFrame(frame, tc.Key, spec)
		if err != nil {
			return 0, fmt.Errorf("%s: validate: %w", tc.ID, err)
		}
		if gotID != sid {
			return 0, fmt.Errorf("%s: session id mismatch", tc.ID)
		}
	}
	return len(f.Cases), nil
}

func checkTCP(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f tcpFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	for _, tc := range f.Cases {
		spec, err := wire.BuildEffectiveSpec(tc.Key, tc.Spec, tc.ALPN)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", tc.ID, err)
		}
		frame, err := wire.EncodeTCPRequest(tc.Target, spec)
		if err != nil {
			return 0, fmt.Errorf("%s: encode: %w", tc.ID, err)
		}
		want, err := decodeHex(tc.FrameHex)
		if err != nil {
			return 0, fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
		}
		if !bytes.Equal(frame, want) {
			return 0, fmt.Errorf("%s: tcp request mismatch\n got %x\nwant %x", tc.ID, frame, want)
		}
	}
	return len(f.Cases), nil
}

func checkCompact(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f compactFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	for _, tc := range f.Cases {
		want, err := decodeHex(tc.FrameHex)
		if err != nil {
			return 0, fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
		}
		var payload []byte
		if tc.PayloadHex != "" {
			payload, err = decodeHex(tc.PayloadHex)
			if err != nil {
				return 0, fmt.Errorf("%s: payload: %w", tc.ID, err)
			}
		}
		var got []byte
		switch tc.TypeByte {
		case wire.UDPTypeOpenData:
			got, err = wire.EncodeUDPOpenData(tc.FlowID, wire.Carrier(tc.DownlinkByte), tc.Target, payload)
		case wire.UDPTypeOpenAck, wire.UDPTypeData, wire.UDPTypeCompactClose:
			got, err = wire.EncodeUDPCompact(tc.TypeByte, tc.FlowID, payload)
		default:
			return 0, fmt.Errorf("%s: unsupported type_byte %d", tc.ID, tc.TypeByte)
		}
		if err != nil {
			return 0, fmt.Errorf("%s: encode: %w", tc.ID, err)
		}
		if !bytes.Equal(got, want) {
			return 0, fmt.Errorf("%s: compact frame mismatch\n got %x\nwant %x", tc.ID, got, want)
		}
		decoded, err := wire.DecodeUDPCompact(got)
		if err != nil {
			return 0, fmt.Errorf("%s: decode: %w", tc.ID, err)
		}
		if decoded.Type != tc.TypeByte || decoded.FlowID != tc.FlowID {
			return 0, fmt.Errorf("%s: decode fields mismatch", tc.ID)
		}
	}
	return len(f.Cases), nil
}

func checkTarget(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f targetFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	spec, err := wire.BuildEffectiveSpec("secret", "auto", "now/1")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, tc := range f.Accept {
		if _, err := wire.EncodeTCPRequest(tc.Target, spec); err != nil {
			return n, fmt.Errorf("%s: expected accept, got %v", tc.ID, err)
		}
		n++
	}
	for _, tc := range f.Reject {
		if _, err := wire.EncodeTCPRequest(tc.Target, spec); err == nil {
			return n, fmt.Errorf("%s: expected reject for %q", tc.ID, tc.Target)
		}
		n++
	}
	return n, nil
}
