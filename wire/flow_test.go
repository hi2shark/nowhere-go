package wire

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/hi2shark/nowhere-go/internal/vectors"
)

func TestFlowCorpusHeaders(t *testing.T) {
	corpus, err := vectors.LoadFlow()
	if err != nil {
		t.Fatalf("LoadFlow: %v", err)
	}
	for _, tc := range corpus.Cases {
		if tc.Operation != "flow_header" {
			continue
		}
		t.Run(tc.ID, func(t *testing.T) {
			frame, err := vectors.DecodeHex(tc.FrameHex)
			if err != nil {
				t.Fatalf("DecodeHex: %v", err)
			}
			if !tc.Valid {
				if _, err := ReadFlowHeader(bytes.NewReader(frame)); err == nil {
					t.Fatal("ReadFlowHeader accepted invalid corpus frame")
				}
				return
			}
			header := flowHeaderFromCorpus(t, tc)
			encoded, err := WriteFlowHeader(header)
			if err != nil {
				t.Fatalf("WriteFlowHeader: %v", err)
			}
			if !bytes.Equal(encoded[:], frame) {
				t.Fatalf("encoded = %x, want corpus %x", encoded, frame)
			}
			decoded, err := ReadFlowHeader(bytes.NewReader(frame))
			if err != nil {
				t.Fatalf("ReadFlowHeader: %v", err)
			}
			if decoded != header {
				t.Fatalf("decoded = %+v, want %+v", decoded, header)
			}
		})
	}

	if FlowHeaderLen != 14 {
		t.Fatalf("FlowHeaderLen = %d, want 14", FlowHeaderLen)
	}
	smoke, err := WriteFlowHeader(FlowHeader{
		Role: FlowRoleDuplex, FlowID: 1, Kind: FlowKindTCP, Uplink: CarrierUDP, Downlink: CarrierUDP,
	})
	if err != nil {
		t.Fatalf("WriteFlowHeader smoke: %v", err)
	}
	if smoke[0] != 0xf1 {
		t.Fatalf("flow magic = %#x, want 0xf1", smoke[0])
	}
}

func TestFlowHeaderRejectsInvalidCarrierShapes(t *testing.T) {
	cases := []FlowHeader{
		{Role: FlowRoleOpen, FlowID: 0, Kind: FlowKindTCP, Uplink: CarrierTCP, Downlink: CarrierUDP},
		{Role: 0, FlowID: 1, Kind: FlowKindTCP, Uplink: CarrierTCP, Downlink: CarrierUDP},
		{Role: FlowRoleOpen, FlowID: 1, Kind: 0, Uplink: CarrierTCP, Downlink: CarrierUDP},
		{Role: FlowRoleOpen, FlowID: 1, Kind: FlowKindTCP, Uplink: 0, Downlink: CarrierUDP},
		{Role: FlowRoleOpen, FlowID: 1, Kind: FlowKindTCP, Uplink: CarrierTCP, Downlink: 0},
		{Role: FlowRoleOpen, FlowID: 1, Kind: FlowKindTCP, Uplink: CarrierTCP, Downlink: CarrierTCP},
		{Role: FlowRoleAttach, FlowID: 1, Kind: FlowKindUDP, Uplink: CarrierUDP, Downlink: CarrierUDP},
		{Role: FlowRoleDuplex, FlowID: 1, Kind: FlowKindTCP, Uplink: CarrierTCP, Downlink: CarrierUDP},
	}
	for _, header := range cases {
		if _, err := WriteFlowHeader(header); err == nil {
			t.Fatalf("WriteFlowHeader accepted invalid shape: %+v", header)
		}
	}
}

func TestFlowCorpusContainsOnlyKnownOperations(t *testing.T) {
	corpus, err := vectors.LoadFlow()
	if err != nil {
		t.Fatalf("LoadFlow: %v", err)
	}
	counts := map[string]int{"flow_header": 0, "flow_result": 0}
	for _, tc := range corpus.Cases {
		if _, ok := counts[tc.Operation]; !ok {
			t.Fatalf("unknown flow corpus operation %q in %s", tc.Operation, tc.ID)
		}
		counts[tc.Operation]++
	}
	for operation, count := range counts {
		if count == 0 {
			t.Fatalf("flow corpus has no %s cases", operation)
		}
	}
}

func TestEncodeFlowSetupAttachIsHeaderOnly(t *testing.T) {
	spec, err := BuildEffectiveSpec("secret", "auto", "now/1")
	if err != nil {
		t.Fatal(err)
	}
	attach := FlowHeader{
		Role: FlowRoleAttach, FlowID: 1, Kind: FlowKindTCP, Uplink: CarrierTCP, Downlink: CarrierUDP,
	}
	attachSetup, err := EncodeFlowSetup(attach, "", nil)
	if err != nil {
		t.Fatalf("EncodeFlowSetup attach: %v", err)
	}
	if len(attachSetup) != FlowHeaderLen {
		t.Fatalf("attach setup length = %d, want %d", len(attachSetup), FlowHeaderLen)
	}

	for _, header := range []FlowHeader{
		{Role: FlowRoleOpen, FlowID: 2, Kind: FlowKindTCP, Uplink: CarrierTCP, Downlink: CarrierUDP},
		{Role: FlowRoleDuplex, FlowID: 3, Kind: FlowKindTCP, Uplink: CarrierTCP, Downlink: CarrierTCP},
	} {
		setup, err := EncodeFlowSetup(header, "example.com:443", spec)
		if err != nil {
			t.Fatalf("EncodeFlowSetup role %d: %v", header.Role, err)
		}
		if len(setup) <= FlowHeaderLen {
			t.Fatalf("role %d setup length = %d, want > %d", header.Role, len(setup), FlowHeaderLen)
		}
	}
}

func flowHeaderFromCorpus(t *testing.T, tc vectors.FlowCase) FlowHeader {
	t.Helper()
	flowID, err := strconv.ParseUint(tc.FlowID, 10, 64)
	if err != nil {
		t.Fatalf("flow_id %q: %v", tc.FlowID, err)
	}
	return FlowHeader{
		Role:     parseFlowRole(t, tc.Role),
		FlowID:   flowID,
		Kind:     parseFlowKind(t, tc.Kind),
		Uplink:   parseCarrier(t, tc.Uplink),
		Downlink: parseCarrier(t, tc.Downlink),
	}
}

func parseFlowRole(t *testing.T, value string) FlowRole {
	t.Helper()
	switch value {
	case "open":
		return FlowRoleOpen
	case "attach":
		return FlowRoleAttach
	case "duplex":
		return FlowRoleDuplex
	default:
		t.Fatalf("unknown flow role %q", value)
		return 0
	}
}

func parseFlowKind(t *testing.T, value string) FlowKind {
	t.Helper()
	switch value {
	case "tcp":
		return FlowKindTCP
	case "udp":
		return FlowKindUDP
	default:
		t.Fatalf("unknown flow kind %q", value)
		return 0
	}
}

func parseCarrier(t *testing.T, value string) Carrier {
	t.Helper()
	switch value {
	case "tls_tcp":
		return CarrierTCP
	case "quic":
		return CarrierUDP
	default:
		t.Fatalf("unknown carrier %q", value)
		return 0
	}
}
