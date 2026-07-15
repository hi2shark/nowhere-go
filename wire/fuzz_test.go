package wire

import (
	"bytes"
	"testing"
)

func fuzzSpec(f *testing.F) *EffectiveSpec {
	f.Helper()
	spec, err := BuildEffectiveSpec("secret", "auto", "now/1")
	if err != nil {
		f.Fatal(err)
	}
	return spec
}

func FuzzValidateAuthFrame(f *testing.F) {
	spec := fuzzSpec(f)
	valid, _, err := MakeAuthFrame("secret", spec)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ValidateAuthFrame(data, "secret", spec) })
}

func FuzzDecodeTCPRequest(f *testing.F) {
	spec := fuzzSpec(f)
	valid, _ := EncodeTCPRequest("example.com:443", spec)
	f.Add(valid)
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = DecodeTCPRequest(bytes.NewReader(data), spec) })
}

func FuzzReadFlowHeader(f *testing.F) {
	valid, _ := WriteFlowHeader(FlowHeader{
		Role: FlowRoleOpen, FlowID: 1, Kind: FlowKindTCP, Uplink: CarrierTCP, Downlink: CarrierUDP,
	})
	f.Add(valid[:])
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ReadFlowHeader(bytes.NewReader(data)) })
}

func FuzzDecodeUDPFrame(f *testing.F) {
	frames, _ := EncodeUDPDataFragments(1, 1, []byte("x"), 1200)
	f.Add(frames[0])
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = DecodeUDPFrame(data) })
}

func FuzzReadUOTFrame(f *testing.F) {
	valid, _ := EncodeUOTFrame(UOTFrame{Kind: UOTFrameData, Payload: []byte("packet")})
	f.Add(valid)
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ReadUOTFrame(bytes.NewReader(data)) })
}

func FuzzBuildEffectiveSpec(f *testing.F) {
	f.Add("secret", "auto", "now/1")
	f.Fuzz(func(t *testing.T, key, spec, alpn string) { _, _ = BuildEffectiveSpec(key, spec, alpn) })
}
