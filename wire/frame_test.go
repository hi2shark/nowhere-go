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
		key     string
		spec    string
		alpn    string
		flowID  uint64
		target  string
		payload []byte
		ftype   uint8
	}{
		{"req-auto", "secret", "auto", "now/1", 1, "1.2.3.4:53", []byte("hello"), UDPTypeRequest},
		{"resp-custom", "key", "custom-spec", "", 0xdeadbeef, "[2001:db8::1]:443", []byte("world!"), UDPTypeResponse},
		{"close-empty", "k", "", "h3", 0xffffffffffffffff, "example.org:80", nil, UDPTypeClose},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := BuildEffectiveSpec(tc.key, tc.spec, tc.alpn)
			if err != nil {
				t.Fatalf("BuildEffectiveSpec: %v", err)
			}
			frame, err := EncodeUDPDatagram(tc.ftype, tc.flowID, tc.target, tc.payload, spec)
			if err != nil {
				t.Fatalf("EncodeUDPDatagram: %v", err)
			}
			// Payload aliases buf; compare before reuse.
			msg, err := DecodeUDPDatagram(frame, spec)
			if err != nil {
				t.Fatalf("DecodeUDPDatagram: %v", err)
			}
			if msg.Type != tc.ftype || msg.FlowID != tc.flowID || msg.Target != tc.target {
				t.Fatalf("header mismatch: type=%d flow=%d target=%q", msg.Type, msg.FlowID, msg.Target)
			}
			if !bytes.Equal(msg.Payload, tc.payload) {
				t.Fatalf("payload mismatch: got %x want %x", msg.Payload, tc.payload)
			}
		})
	}
}

func TestUDPFrameRejects(t *testing.T) {
	spec, err := BuildEffectiveSpec("secret", "auto", "now/1")
	if err != nil {
		t.Fatalf("BuildEffectiveSpec: %v", err)
	}
	if _, err := EncodeUDPDatagram(9, 1, "h:1", nil, spec); err == nil {
		t.Fatalf("EncodeUDPDatagram accepted bad type")
	}
	if _, err := DecodeUDPDatagram([]byte{0x01, 0x02}, spec); err == nil {
		t.Fatalf("DecodeUDPDatagram accepted short buffer")
	}
	frame, err := EncodeUDPDatagram(UDPTypeResponse, 7, "h:1", []byte("x"), spec)
	if err != nil {
		t.Fatalf("EncodeUDPDatagram: %v", err)
	}
	corrupt := append([]byte(nil), frame...)
	corrupt[0] ^= 0xff
	if _, err := DecodeUDPDatagram(corrupt, spec); err == nil {
		t.Fatalf("DecodeUDPDatagram accepted corrupt version")
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
	setup, err := EncodeUOTSetupTarget("[::1]:443")
	if err != nil {
		t.Fatalf("EncodeUOTSetupTarget: %v", err)
	}
	if int(setup[0])<<8|int(setup[1]) != len("[::1]:443") {
		t.Fatalf("setup length prefix wrong: %x", setup[:2])
	}

	pkt := []byte("payload bytes")
	frame, err := WriteUOTPacketFrame(pkt)
	if err != nil {
		t.Fatalf("WriteUOTPacketFrame: %v", err)
	}
	got, consumed, err := ReadUOTPacketFrame(frame)
	if err != nil {
		t.Fatalf("ReadUOTPacketFrame: %v", err)
	}
	if consumed != len(frame) || !bytes.Equal(got, pkt) {
		t.Fatalf("packet mismatch: got %x consumed %d", got, consumed)
	}

	big := make([]byte, 0x10000)
	if _, err := WriteUOTPacketFrame(big); err == nil {
		t.Fatalf("WriteUOTPacketFrame accepted oversized payload")
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

func TestCompactUDPFrameRoundTrip(t *testing.T) {
	// OPEN_DATA downlink carrier byte must round-trip (Portal pairing key).
	enc, err := EncodeUDPOpenData(0xdeadbeef, CarrierTCP, "1.2.3.4:53", []byte("payload"))
	if err != nil {
		t.Fatalf("EncodeUDPOpenData: %v", err)
	}
	dec, err := DecodeUDPCompact(enc)
	if err != nil {
		t.Fatalf("DecodeUDPCompact: %v", err)
	}
	if dec.Type != UDPTypeOpenData || dec.FlowID != 0xdeadbeef || dec.Downlink != CarrierTCP ||
		dec.Target != "1.2.3.4:53" || string(dec.Payload) != "payload" {
		t.Fatalf("open data mismatch: %+v", dec)
	}

	ack, err := EncodeUDPCompact(UDPTypeOpenAck, 7, nil)
	if err != nil {
		t.Fatalf("EncodeUDPCompact ack: %v", err)
	}
	if got, err := DecodeUDPCompact(ack); err != nil || got.Type != UDPTypeOpenAck || got.FlowID != 7 {
		t.Fatalf("ack round-trip: got %+v err %v", got, err)
	}

	data, err := EncodeUDPCompact(UDPTypeData, 7, []byte("xx"))
	if err != nil {
		t.Fatalf("EncodeUDPCompact data: %v", err)
	}
	if got, err := DecodeUDPCompact(data); err != nil || got.Type != UDPTypeData ||
		got.FlowID != 7 || string(got.Payload) != "xx" {
		t.Fatalf("data round-trip: got %+v err %v", got, err)
	}

	cl, err := EncodeUDPCompact(UDPTypeCompactClose, 7, nil)
	if err != nil {
		t.Fatalf("EncodeUDPCompact close: %v", err)
	}
	if got, err := DecodeUDPCompact(cl); err != nil || got.Type != UDPTypeCompactClose || got.FlowID != 7 {
		t.Fatalf("close round-trip: got %+v err %v", got, err)
	}
}

func TestCompactUDPFrameRejects(t *testing.T) {
	if _, err := EncodeUDPOpenData(0, CarrierUDP, "h:1", nil); err == nil {
		t.Fatalf("EncodeUDPOpenData accepted zero flow id")
	}
	if _, err := EncodeUDPCompact(UDPTypeData, 0, nil); err == nil {
		t.Fatalf("EncodeUDPCompact accepted zero flow id")
	}
	if _, err := EncodeUDPCompact(UDPTypeOpenAck, 1, []byte("x")); err == nil {
		t.Fatalf("EncodeUDPCompact accepted payload on control frame")
	}
	if _, err := EncodeUDPCompact(0x99, 1, nil); err == nil {
		t.Fatalf("EncodeUDPCompact accepted bad type")
	}
	short := []byte{ProxyFrameVersion, UDPTypeOpenData, 0, 0, 0, 0, 0, 0, 0, 1, 1}
	if _, err := DecodeUDPCompact(short); err == nil {
		t.Fatalf("DecodeUDPCompact accepted short OPEN_DATA")
	}
	bad := []byte{0x02, UDPTypeData, 0, 0, 0, 0, 0, 0, 0, 1}
	if _, err := DecodeUDPCompact(bad); err == nil {
		t.Fatalf("DecodeUDPCompact accepted wrong version")
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
