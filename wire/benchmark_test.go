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

func BenchmarkDecodeUDPFrame(b *testing.B) {
	frames, _ := EncodeUDPDataFragments(1, 1, []byte("payload"), 1200)
	frame := frames[0]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeUDPFrame(frame)
	}
}

func TestWireAllocationBounds(t *testing.T) {
	spec, _ := BuildEffectiveSpec("secret", "auto", "now/1")
	auth, _, _ := MakeAuthFrame("secret", spec)
	tcp, _ := EncodeTCPRequest("example.com:443", spec)
	udpFrames, _ := EncodeUDPDataFragments(1, 1, []byte("payload"), 1200)
	udp := udpFrames[0]
	uot, _ := EncodeUOTFrame(UOTFrame{Kind: UOTFrameData, Payload: []byte("payload")})

	if allocations := testing.AllocsPerRun(100, func() { _, _ = ValidateAuthFrame(auth, "secret", spec) }); allocations > 20 {
		t.Fatalf("ValidateAuthFrame allocations %.1f exceed 20", allocations)
	}
	if allocations := testing.AllocsPerRun(100, func() { _, _ = DecodeTCPRequest(bytes.NewReader(tcp), spec) }); allocations > 24 {
		t.Fatalf("DecodeTCPRequest allocations %.1f exceed 24", allocations)
	}
	if allocations := testing.AllocsPerRun(100, func() { _, _ = DecodeUDPFrame(udp) }); allocations > 6 {
		t.Fatalf("DecodeUDPFrame allocations %.1f exceed 6", allocations)
	}
	_ = uot
}
