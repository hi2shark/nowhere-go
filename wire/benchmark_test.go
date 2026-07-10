package wire

import (
	"bytes"
	"testing"
)

func BenchmarkValidateAuthFrame(b *testing.B) {
	spec, _ := BuildEffectiveSpec("secret", "auto", "now/1")
	frame, _, _ := MakeAuthFrame("secret", spec)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ValidateAuthFrame(frame, "secret", spec)
	}
}

func BenchmarkDecodeTCPRequest(b *testing.B) {
	spec, _ := BuildEffectiveSpec("secret", "auto", "now/1")
	frame, _ := EncodeTCPRequest("example.com:443", spec)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeTCPRequest(bytes.NewReader(frame), spec)
	}
}

func BenchmarkDecodeUDPCompact(b *testing.B) {
	frame, _ := EncodeUDPOpenData(1, CarrierUDP, "example.com:53", []byte("payload"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeUDPCompact(frame)
	}
}

func TestWireAllocationBounds(t *testing.T) {
	spec, _ := BuildEffectiveSpec("secret", "auto", "now/1")
	auth, _, _ := MakeAuthFrame("secret", spec)
	tcp, _ := EncodeTCPRequest("example.com:443", spec)
	compact, _ := EncodeUDPOpenData(1, CarrierUDP, "example.com:53", []byte("payload"))

	if allocations := testing.AllocsPerRun(100, func() { _, _ = ValidateAuthFrame(auth, "secret", spec) }); allocations > 20 {
		t.Fatalf("ValidateAuthFrame allocations %.1f exceed 20", allocations)
	}
	if allocations := testing.AllocsPerRun(100, func() { _, _ = DecodeTCPRequest(bytes.NewReader(tcp), spec) }); allocations > 24 {
		t.Fatalf("DecodeTCPRequest allocations %.1f exceed 24", allocations)
	}
	if allocations := testing.AllocsPerRun(100, func() { _, _ = DecodeUDPCompact(compact) }); allocations > 4 {
		t.Fatalf("DecodeUDPCompact allocations %.1f exceed 4", allocations)
	}
}
