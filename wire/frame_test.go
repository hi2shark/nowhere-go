package wire

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Conformance vectors (protocol.md §7.2 / §14); auth includes trailing session_id.
const (
	vectorKey    = "secret"
	vectorSpec   = "auto"
	vectorALPN   = "now/1"
	vectorNonce  = "0707070707070707070707070707070707070707070707070707070707070707"
	vectorTarget = "example.com:443"

	// spec=auto, key=secret, nonce=0x07*32, session_id=0*16 (94 bytes).
	vectorAuthHex = "9f5c48262539a0c11b36f1c68104707b" +
		"5e8ed40b43095a4bbf116a0841d627bb" +
		"d065c573fe8427ef" +
		"058b0eb2d90a" +
		"0707070707070707070707070707070707070707070707070707070707070707" +
		"00000000000000000000000000000000"

	// spec=edge-a (different derived padding).
	vectorAuthEdgeAHex = "4aac8618aec3963e460c00ef25b0b998" +
		"a1fa9057caff3c7022cd7d4bcae1eaa6" +
		"1e45f46ff130d784" +
		"3823958bb0fc0e8e" +
		"ebd66a60e5fab1f83233cb5e4e8c4344" +
		"dfe8d3da0bdf90" +
		"0707070707070707070707070707070707070707070707070707070707070707" +
		"00000000000000000000000000000000"

	vectorTCPHex = "000f6578616d706c652e636f6d3a343433013c1526b9b947228779cfc539fe4" +
		"681bcb5d1e20efa2bcb9f89eda5b473625c3c6b7fb12499fd33edfefb1934c" +
		"9ae0bfc0e849f4c94814f4f2f9ae782e8"
)

func cleanHex(t *testing.T, h string) []byte {
	t.Helper()
	out := make([]byte, 0, len(h)/2)
	for _, r := range h {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			out = append(out, byte(r))
		}
	}
	b, err := hex.DecodeString(string(out))
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

func TestProtocolVectorsAuthFrame(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		wantHex string
	}{
		{"auto", vectorSpec, vectorAuthHex},
		{"edge-a", "edge-a", vectorAuthEdgeAHex},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := BuildEffectiveSpec(vectorKey, tc.spec, vectorALPN)
			if err != nil {
				t.Fatalf("BuildEffectiveSpec: %v", err)
			}
			nonce, err := hex.DecodeString(vectorNonce)
			if err != nil {
				t.Fatalf("nonce decode: %v", err)
			}
			frame, err := MakeAuthFrameWithNonce(vectorKey, spec, nonce, SessionID{})
			if err != nil {
				t.Fatalf("MakeAuthFrameWithNonce: %v", err)
			}
			want := cleanHex(t, tc.wantHex)
			if !bytes.Equal(frame, want) {
				t.Fatalf("auth frame mismatch\n got %x\nwant %x", frame, want)
			}

			gotID, err := ValidateAuthFrame(frame, vectorKey, spec)
			if err != nil {
				t.Fatalf("ValidateAuthFrame: %v", err)
			}
			if gotID != (SessionID{}) {
				t.Fatalf("session id = %x, want all-zero", gotID)
			}
			if _, err := ValidateAuthFrame(frame, "wrong", spec); err == nil {
				t.Fatalf("ValidateAuthFrame accepted wrong key")
			}
		})
	}
}

func TestProtocolVectorsTCPRequest(t *testing.T) {
	spec, err := BuildEffectiveSpec(vectorKey, vectorSpec, vectorALPN)
	if err != nil {
		t.Fatalf("BuildEffectiveSpec: %v", err)
	}
	frame, err := EncodeTCPRequest(vectorTarget, spec)
	if err != nil {
		t.Fatalf("EncodeTCPRequest: %v", err)
	}
	want := cleanHex(t, vectorTCPHex)
	if !bytes.Equal(frame, want) {
		t.Fatalf("tcp request mismatch\n got %x\nwant %x", frame, want)
	}
}

func TestUDPFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		flowID  uint64
		payload []byte
		maxSize int
	}{
		{"single", 1, []byte("hello"), 1200},
		{"multi", 11, bytes.Repeat([]byte{0x5a}, 2500), 1200},
		{"empty", 5, []byte{}, 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frames, err := EncodeUDPDataFragments(tc.flowID, 1, tc.payload, tc.maxSize)
			if err != nil {
				t.Fatalf("EncodeUDPDataFragments: %v", err)
			}
			var assembled []byte
			for i, frame := range frames {
				if len(frame) > tc.maxSize {
					t.Fatalf("frame %d len %d exceeds max", i, len(frame))
				}
				decoded, err := DecodeUDPFrame(frame)
				if err != nil {
					t.Fatalf("DecodeUDPFrame frame %d: %v", i, err)
				}
				if decoded.Type != UDPFrameData {
					t.Fatalf("frame %d type = %d", i, decoded.Type)
				}
				if decoded.FlowID != tc.flowID {
					t.Fatalf("frame %d flow id = %d", i, decoded.FlowID)
				}
				assembled = append(assembled, decoded.Fragment.Payload...)
			}
			if !bytes.Equal(assembled, tc.payload) {
				t.Fatalf("payload mismatch: got %x want %x", assembled, tc.payload)
			}
		})
	}
}

func TestUDPFrameRejects(t *testing.T) {
	if _, err := EncodeUDPDataFragments(0, 1, []byte("x"), 64); err == nil {
		t.Fatalf("EncodeUDPDataFragments accepted zero flow id")
	}
	if _, err := DecodeUDPFrame([]byte{0x01, 0x02}); err == nil {
		t.Fatalf("DecodeUDPFrame accepted short buffer")
	}
	closeFrame, _ := EncodeUDPClose(7)
	closeFrame = append(closeFrame, 0)
	if _, err := DecodeUDPFrame(closeFrame); err == nil {
		t.Fatalf("DecodeUDPFrame accepted close with payload")
	}
}

func TestTCPRequestRejects(t *testing.T) {
	spec, err := BuildEffectiveSpec("secret", "auto", "now/1")
	if err != nil {
		t.Fatalf("BuildEffectiveSpec: %v", err)
	}
	bad := []string{
		"",                 // empty
		"no-port",          // missing port
		":",                // empty port
		"a:b:c",            // too many colons (unbracketed)
		"[2001:db8::1",     // missing ]
		"[2001:db8::1]443", // missing : before port
		strings.Repeat("a", maxTargetLength+1) + ":1", // too long
	}
	for _, target := range bad {
		if _, err := EncodeTCPRequest(target, spec); err == nil {
			t.Fatalf("EncodeTCPRequest accepted %q", target)
		}
	}
	good := []string{
		"example.com:443",
		"1.2.3.4:80",
		"[2001:db8::1]:443",
		"[::1]:53",
	}
	for _, target := range good {
		if _, err := EncodeTCPRequest(target, spec); err != nil {
			t.Fatalf("EncodeTCPRequest rejected good %q: %v", target, err)
		}
	}
}

func TestUOTFraming(t *testing.T) {
	pkt := []byte("payload bytes")
	frame, err := EncodeUOTFrame(UOTFrame{Kind: UOTFrameData, Payload: pkt})
	if err != nil {
		t.Fatalf("EncodeUOTFrame: %v", err)
	}
	got, err := ReadUOTFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("ReadUOTFrame: %v", err)
	}
	if got.Kind != UOTFrameData || !bytes.Equal(got.Payload, pkt) {
		t.Fatalf("packet mismatch: got %+v", got)
	}

	big := make([]byte, 0x10000)
	if _, err := EncodeUOTFrame(UOTFrame{Kind: UOTFrameData, Payload: big}); err == nil {
		t.Fatalf("EncodeUOTFrame accepted oversized payload")
	}
	if _, err := EncodeUOTFrame(UOTFrame{Kind: UOTFrameReady, Payload: []byte{1}}); err == nil {
		t.Fatal("EncodeUOTFrame accepted READY with payload")
	}
}

func TestAuthFrameValidation(t *testing.T) {
	spec, err := BuildEffectiveSpec("secret", "auto", "now/1")
	if err != nil {
		t.Fatalf("BuildEffectiveSpec: %v", err)
	}
	frame, sessionID, err := MakeAuthFrame("secret", spec)
	if err != nil {
		t.Fatalf("MakeAuthFrame: %v", err)
	}
	if got, err := ValidateAuthFrame(frame, "secret", spec); err != nil {
		t.Fatalf("ValidateAuthFrame valid: %v", err)
	} else if got != sessionID {
		t.Fatalf("session id mismatch: got %x want %x", got, sessionID)
	}
	if _, err := ValidateAuthFrame(frame, "wrong-key", spec); err == nil {
		t.Fatal("ValidateAuthFrame accepted wrong key")
	}
	wrongSpec, err := BuildEffectiveSpec("secret", "edge-a", "now/1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAuthFrame(frame, "secret", wrongSpec); err == nil {
		t.Fatal("ValidateAuthFrame accepted wrong spec")
	}
	// session_id is under the HMAC; any single-byte tamper must fail.
	for i := range frame {
		tampered := append([]byte(nil), frame...)
		tampered[i] ^= 0x01
		if _, err := ValidateAuthFrame(tampered, "secret", spec); err == nil {
			t.Fatalf("ValidateAuthFrame accepted tampered byte %d", i)
		}
	}
	// Wrong length must fail.
	short := frame[:len(frame)-1]
	if _, err := ValidateAuthFrame(short, "secret", spec); err == nil {
		t.Fatalf("ValidateAuthFrame accepted short frame")
	}
}

func TestSplitHostPortEmpty(t *testing.T) {
	if _, err := splitHostPort(""); err == nil {
		t.Fatal("expected error for empty target")
	}
	if err := validateTarget(""); err == nil {
		t.Fatal("expected validateTarget error for empty")
	}
}
