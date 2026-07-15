package wire

import (
	"bytes"
	"testing"
)

func TestDecodeTCPRequestRoundTrip(t *testing.T) {
	spec, err := BuildEffectiveSpec("secret", "auto", "now/1")
	if err != nil {
		t.Fatalf("BuildEffectiveSpec: %v", err)
	}
	frame, err := EncodeTCPRequest("example.com:443", spec)
	if err != nil {
		t.Fatalf("EncodeTCPRequest: %v", err)
	}
	got, err := DecodeTCPRequest(bytes.NewReader(frame), spec)
	if err != nil {
		t.Fatalf("DecodeTCPRequest: %v", err)
	}
	if got != "example.com:443" {
		t.Fatalf("target = %q", got)
	}
}

func TestReadAuthFrameRoundTrip(t *testing.T) {
	spec, err := BuildEffectiveSpec("secret", "auto", "now/1")
	if err != nil {
		t.Fatalf("BuildEffectiveSpec: %v", err)
	}
	frame, sid, err := MakeAuthFrame("secret", spec)
	if err != nil {
		t.Fatalf("MakeAuthFrame: %v", err)
	}
	got, err := ReadAuthFrame(bytes.NewReader(frame), "secret", spec)
	if err != nil {
		t.Fatalf("ReadAuthFrame: %v", err)
	}
	if got != sid {
		t.Fatalf("session id mismatch")
	}
}
