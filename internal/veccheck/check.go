// Package veccheck validates Nowhere harness vectors against the wire codecs.
package veccheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/hi2shark/nowhere-go/internal/vectors"
	"github.com/hi2shark/nowhere-go/wire"
)

type authFile struct {
	Cases []struct {
		ID           string `json:"id"`
		Key          string `json:"key"`
		Spec         string `json:"spec"`
		ALPN         string `json:"alpn"`
		NonceHex     string `json:"nonce_hex"`
		SessionIDHex string `json:"session_id_hex"`
		FrameHex     string `json:"frame_hex"`
		FrameLen     int    `json:"frame_len"`
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

type flowFile struct {
	Cases []struct {
		ID        string `json:"id"`
		Operation string `json:"operation"`
		Valid     bool   `json:"valid"`
		Role      string `json:"role"`
		FlowID    string `json:"flow_id"`
		Kind      string `json:"kind"`
		Uplink    string `json:"uplink"`
		Downlink  string `json:"downlink"`
		Status    string `json:"status"`
		Code      uint8  `json:"code"`
		FrameHex  string `json:"frame_hex"`
		ErrorCode string `json:"error_code"`
	} `json:"cases"`
}

type nowuFile struct {
	Cases []struct {
		ID              string   `json:"id"`
		Operation       string   `json:"operation"`
		Valid           bool     `json:"valid"`
		FlowID          string   `json:"flow_id"`
		PacketID        uint32   `json:"packet_id"`
		MaxDatagramSize int      `json:"max_datagram_size"`
		PayloadHex      string   `json:"payload_hex"`
		FramesHex       []string `json:"frames_hex"`
		RawHex          string   `json:"raw_hex"`
		ErrorCode       string   `json:"error_code"`
	} `json:"cases"`
}

type uotFile struct {
	Cases []struct {
		ID         string `json:"id"`
		Valid      bool   `json:"valid"`
		Kind       string `json:"kind"`
		PayloadHex string `json:"payload_hex"`
		Code       uint8  `json:"code"`
		FrameHex   string `json:"frame_hex"`
		ErrorCode  string `json:"error_code"`
	} `json:"cases"`
}

// CheckDir validates all known vector files under dir. Returns number of cases checked.
func CheckDir(dir string) (int, error) {
	n := 0
	checkers := []struct {
		name string
		fn   func(string) (int, error)
	}{
		{"auth.json", checkAuth},
		{"tcp_request.json", checkTCP},
		{"target_addr.json", checkTarget},
		{"flow.json", checkFlow},
		{"udp_nowu.json", checkNowu},
		{"uot_typed.json", checkUOT},
	}
	for _, c := range checkers {
		count, err := c.fn(filepath.Join(dir, c.name))
		if err != nil {
			return n, err
		}
		n += count
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
		nonce, err := vectors.DecodeHex(tc.NonceHex)
		if err != nil {
			return 0, fmt.Errorf("%s: nonce: %w", tc.ID, err)
		}
		var sid wire.SessionID
		sidBytes, err := vectors.DecodeHex(tc.SessionIDHex)
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
		want, err := vectors.DecodeHex(tc.FrameHex)
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
		want, err := vectors.DecodeHex(tc.FrameHex)
		if err != nil {
			return 0, fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
		}
		if !bytes.Equal(frame, want) {
			return 0, fmt.Errorf("%s: tcp request mismatch\n got %x\nwant %x", tc.ID, frame, want)
		}
	}
	return len(f.Cases), nil
}

func carrierFrom(s string) wire.Carrier {
	switch s {
	case "tls_tcp":
		return wire.CarrierTCP
	case "quic":
		return wire.CarrierUDP
	default:
		return 0
	}
}

func flowRoleFrom(s string) wire.FlowRole {
	switch s {
	case "open":
		return wire.FlowRoleOpen
	case "attach":
		return wire.FlowRoleAttach
	case "duplex":
		return wire.FlowRoleDuplex
	default:
		return 0
	}
}

func flowKindFrom(s string) wire.FlowKind {
	switch s {
	case "tcp":
		return wire.FlowKindTCP
	case "udp":
		return wire.FlowKindUDP
	default:
		return 0
	}
}

func checkFlow(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f flowFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	for _, tc := range f.Cases {
		want, err := vectors.DecodeHex(tc.FrameHex)
		if err != nil {
			return 0, fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
		}
		switch tc.Operation {
		case "flow_header":
			header := wire.FlowHeader{
				Role:     flowRoleFrom(tc.Role),
				FlowID:   parseFlowID(tc.FlowID),
				Kind:     flowKindFrom(tc.Kind),
				Uplink:   carrierFrom(tc.Uplink),
				Downlink: carrierFrom(tc.Downlink),
			}
			got, err := wire.WriteFlowHeader(header)
			if tc.Valid {
				if err != nil {
					return 0, fmt.Errorf("%s: encode: %w", tc.ID, err)
				}
				if !bytes.Equal(got[:], want) {
					return 0, fmt.Errorf("%s: flow header mismatch\n got %x\nwant %x", tc.ID, got[:], want)
				}
				decoded, err := wire.ReadFlowHeader(bytes.NewReader(want))
				if err != nil {
					return 0, fmt.Errorf("%s: decode: %w", tc.ID, err)
				}
				if decoded != header {
					return 0, fmt.Errorf("%s: decoded header mismatch", tc.ID)
				}
			} else {
				if _, decodeErr := wire.ReadFlowHeader(bytes.NewReader(want)); decodeErr != nil {
					continue
				}
				if err == nil {
					return 0, fmt.Errorf("%s: expected encode error", tc.ID)
				}
			}
		case "flow_result":
			status := wire.FlowStatusReady
			switch tc.Status {
			case "reject":
				status = wire.FlowStatusReject
			case "invalid":
				status = 9
			}
			result := wire.FlowResult{Status: status, Code: wire.FlowErrorCode(tc.Code)}
			got, err := wire.WriteFlowResult(result)
			if tc.Valid {
				if err != nil {
					return 0, fmt.Errorf("%s: encode: %w", tc.ID, err)
				}
				if !bytes.Equal(got[:], want) {
					return 0, fmt.Errorf("%s: flow result mismatch\n got %x\nwant %x", tc.ID, got[:], want)
				}
				decoded, err := wire.ReadFlowResult(bytes.NewReader(want))
				if err != nil {
					return 0, fmt.Errorf("%s: decode: %w", tc.ID, err)
				}
				if decoded != result {
					return 0, fmt.Errorf("%s: decoded result mismatch", tc.ID)
				}
			} else {
				if _, decodeErr := wire.ReadFlowResult(bytes.NewReader(want)); decodeErr != nil {
					continue
				}
				if err == nil {
					return 0, fmt.Errorf("%s: expected encode error", tc.ID)
				}
			}
		default:
			return 0, fmt.Errorf("%s: unknown operation %q", tc.ID, tc.Operation)
		}
	}
	return len(f.Cases), nil
}

func parseFlowID(s string) uint64 {
	if s == "" {
		return 0
	}
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return id
}

func checkNowu(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f nowuFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	for _, tc := range f.Cases {
		flowID := parseFlowID(tc.FlowID)
		payload, err := vectors.DecodeHex(tc.PayloadHex)
		if err != nil {
			return 0, fmt.Errorf("%s: payload: %w", tc.ID, err)
		}
		switch tc.Operation {
		case "data":
			frames, err := wire.EncodeUDPDataFragments(flowID, tc.PacketID, payload, tc.MaxDatagramSize)
			if err != nil {
				return 0, fmt.Errorf("%s: encode: %w", tc.ID, err)
			}
			if len(frames) != len(tc.FramesHex) {
				return 0, fmt.Errorf("%s: frame count %d want %d", tc.ID, len(frames), len(tc.FramesHex))
			}
			for i, got := range frames {
				want, err := vectors.DecodeHex(tc.FramesHex[i])
				if err != nil {
					return 0, fmt.Errorf("%s: frames_hex[%d]: %w", tc.ID, i, err)
				}
				if !bytes.Equal(got, want) {
					return 0, fmt.Errorf("%s: frame[%d] mismatch\n got %x\nwant %x", tc.ID, i, got, want)
				}
				decoded, err := wire.DecodeUDPFrame(got)
				if err != nil {
					return 0, fmt.Errorf("%s: decode frame[%d]: %w", tc.ID, i, err)
				}
				if decoded.Type != wire.UDPFrameData || decoded.FlowID != flowID {
					return 0, fmt.Errorf("%s: decoded frame[%d] fields mismatch", tc.ID, i)
				}
			}
		case "close":
			got, err := wire.EncodeUDPClose(flowID)
			if err != nil {
				return 0, fmt.Errorf("%s: encode: %w", tc.ID, err)
			}
			want, err := vectors.DecodeHex(tc.FramesHex[0])
			if err != nil {
				return 0, fmt.Errorf("%s: frames_hex[0]: %w", tc.ID, err)
			}
			if !bytes.Equal(got, want) {
				return 0, fmt.Errorf("%s: close frame mismatch\n got %x\nwant %x", tc.ID, got, want)
			}
		case "decode":
			rawFrame, err := vectors.DecodeHex(tc.RawHex)
			if err != nil {
				return 0, fmt.Errorf("%s: raw_hex: %w", tc.ID, err)
			}
			_, err = wire.DecodeUDPFrame(rawFrame)
			if tc.Valid {
				if err != nil {
					return 0, fmt.Errorf("%s: decode: %w", tc.ID, err)
				}
			} else {
				if err == nil {
					return 0, fmt.Errorf("%s: expected decode error (%s)", tc.ID, tc.ErrorCode)
				}
			}
		default:
			return 0, fmt.Errorf("%s: unknown operation %q", tc.ID, tc.Operation)
		}
	}
	return len(f.Cases), nil
}

func uotKindFrom(s string) wire.UOTFrameKind {
	switch s {
	case "data":
		return wire.UOTFrameData
	case "ready":
		return wire.UOTFrameReady
	case "close":
		return wire.UOTFrameClose
	case "reject":
		return wire.UOTFrameReject
	default:
		return 0
	}
}

func checkUOT(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f uotFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	for _, tc := range f.Cases {
		payload, err := vectors.DecodeHex(tc.PayloadHex)
		if err != nil {
			return 0, fmt.Errorf("%s: payload: %w", tc.ID, err)
		}
		kind := uotKindFrom(tc.Kind)
		frame := wire.UOTFrame{Kind: kind, Payload: payload, Code: wire.FlowErrorCode(tc.Code)}
		got, err := wire.EncodeUOTFrame(frame)
		if tc.Valid {
			if err != nil {
				return 0, fmt.Errorf("%s: encode: %w", tc.ID, err)
			}
			want, err := vectors.DecodeHex(tc.FrameHex)
			if err != nil {
				return 0, fmt.Errorf("%s: frame_hex: %w", tc.ID, err)
			}
			if !bytes.Equal(got, want) {
				return 0, fmt.Errorf("%s: uot frame mismatch\n got %x\nwant %x", tc.ID, got, want)
			}
			decoded, err := wire.ReadUOTFrame(bytes.NewReader(want))
			if err != nil {
				return 0, fmt.Errorf("%s: decode: %w", tc.ID, err)
			}
			if decoded.Kind != kind {
				return 0, fmt.Errorf("%s: decoded kind mismatch", tc.ID)
			}
		} else {
			if err == nil {
				return 0, fmt.Errorf("%s: expected encode error (%s)", tc.ID, tc.ErrorCode)
			}
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
