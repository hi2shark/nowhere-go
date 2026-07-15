package vectors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// FlowFile is the harness flow.json corpus.
type FlowFile struct {
	Cases []FlowCase `json:"cases"`
}

// FlowCase is one flow header or flow result vector.
type FlowCase struct {
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
}

// UDPFile is the harness udp_nowu.json corpus.
type UDPFile struct {
	Cases []UDPCase `json:"cases"`
}

// UDPCase is one NOWU encode/decode vector.
type UDPCase struct {
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
}

// UOTFile is the harness uot_typed.json corpus.
type UOTFile struct {
	Cases []UOTCase `json:"cases"`
}

// UOTCase is one typed UoT frame vector.
type UOTCase struct {
	ID         string `json:"id"`
	Valid      bool   `json:"valid"`
	Kind       string `json:"kind"`
	PayloadHex string `json:"payload_hex"`
	Code       uint8  `json:"code"`
	FrameHex   string `json:"frame_hex"`
	ErrorCode  string `json:"error_code"`
}

// LoadFlow loads flow.json from Dir().
func LoadFlow() (FlowFile, error) {
	return loadJSON[FlowFile]("flow.json")
}

// LoadUDP loads udp_nowu.json from Dir().
func LoadUDP() (UDPFile, error) {
	return loadJSON[UDPFile]("udp_nowu.json")
}

// LoadUOT loads uot_typed.json from Dir().
func LoadUOT() (UOTFile, error) {
	return loadJSON[UOTFile]("uot_typed.json")
}

func loadJSON[T any](name string) (T, error) {
	var out T
	dir, err := Dir()
	if err != nil {
		return out, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}
