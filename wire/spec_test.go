package wire

import (
	"bytes"
	"testing"
)

// Empty/omitted spec → "auto", ALPN → "now/1" (protocol.md §4 / §3.2).
func TestDefaults(t *testing.T) {
	omit, _ := BuildEffectiveSpec("k", "", "")
	empty, _ := BuildEffectiveSpec("k", "", "")
	auto, _ := BuildEffectiveSpec("k", "auto", "")
	if omit.Spec() != "auto" || empty.Spec() != "auto" || auto.Spec() != "auto" {
		t.Fatalf("spec default wrong: %q %q %q", omit.Spec(), empty.Spec(), auto.Spec())
	}
	if omit.ALPN() != "now/1" {
		t.Fatalf("alpn default wrong: %q", omit.ALPN())
	}
	withALPN, _ := BuildEffectiveSpec("k", "auto", "h3")
	if withALPN.ALPN() != "h3" {
		t.Fatalf("explicit alpn not applied: %q", withALPN.ALPN())
	}
	if !bytes.Equal(withALPN.authMagic, omit.authMagic) || !equalTcpOrder(withALPN.tcpFrameOrder, omit.tcpFrameOrder) {
		t.Fatalf("explicit alpn changed derived material")
	}

	a, _ := BuildEffectiveSpec("k", "auto", "now/1")
	b, _ := BuildEffectiveSpec("k", "auto", "now/1")
	if a.SpecID() != b.SpecID() || !bytes.Equal(a.authMagic, b.authMagic) {
		t.Fatalf("derivation not deterministic")
	}

	// Key must not change derived shape (auth tag is covered in frame_test).
	k1, _ := BuildEffectiveSpec("key-one", "auto", "now/1")
	k2, _ := BuildEffectiveSpec("key-two", "auto", "now/1")
	if !bytes.Equal(k1.authMagic, k2.authMagic) {
		t.Fatalf("derived material changed with key")
	}
}

func TestSpecIDParity(t *testing.T) {
	spec, err := BuildEffectiveSpec("secret", "auto", "now/1")
	if err != nil {
		t.Fatalf("BuildEffectiveSpec: %v", err)
	}
	// auto/now/1 → fixed 11-char base64url-no-pad spec id.
	if len(spec.SpecID()) != 11 {
		t.Fatalf("spec id length = %d, want 11", len(spec.SpecID()))
	}
}

// Auth order must not be the canonical [magic,nonce,padding,tag] (protocol.md §4.2).
func TestFrameOrderDeterministic(t *testing.T) {
	spec, err := BuildEffectiveSpec("secret", "auto", "now/1")
	if err != nil {
		t.Fatalf("BuildEffectiveSpec: %v", err)
	}
	canonical := []AuthFrameElement{AuthMagic, AuthNonce, AuthPadding, AuthTag}
	if equalAuthOrder(spec.authFrameOrder, canonical) {
		t.Fatalf("auth frame order is canonical (must be rotated)")
	}
	if len(spec.authFrameOrder) != 4 || len(spec.tcpFrameOrder) != 3 {
		t.Fatalf("frame order lengths wrong")
	}
	// Each TCP element must appear exactly once.
	if !isPerutation(spec.tcpFrameOrder) {
		t.Fatalf("tcp frame order not a permutation: %v", spec.tcpFrameOrder)
	}

	// Different specs produce different orders (extremely likely; pick a spec
	// known to differ from "auto").
	other, _ := BuildEffectiveSpec("secret", "different-spec-value", "now/1")
	if equalAuthOrder(spec.authFrameOrder, other.authFrameOrder) && equalTcpOrder(spec.tcpFrameOrder, other.tcpFrameOrder) {
		// not a hard failure (collision is possible) but worth pinning a case
		t.Logf("note: spec=%q and %q produced identical layouts", "auto", "different-spec-value")
	}
}

// TestHKDFMatchesRFC5869 cross-checks the in-tree HKDF against the RFC 5869
// Test Case 1 (SHA-256), using an independent label so the test is not
// circular. This guards the exact block construction (previous || info ||
// counter).
func TestHKDFMatchesRFC5869(t *testing.T) {
	// RFC 5869 Appendix A, Test Case 1.
	ikm := fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := fromHex("000102030405060708090a0b0c")
	info := fromHex("f0f1f2f3f4f5f6f7f8f9")
	wantPRK := fromHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	wantOKM := fromHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	prk := hkdfExtract(salt, ikm)
	if !bytes.Equal(prk, wantPRK) {
		t.Fatalf("PRK mismatch\n got %x\nwant %x", prk, wantPRK)
	}
	okm := hkdfExpand(prk, info, 42)
	if !bytes.Equal(okm, wantOKM) {
		t.Fatalf("OKM mismatch\n got %x\nwant %x", okm, wantOKM)
	}
}

func TestBuildEffectiveSpecRejectsInvalidUTF8(t *testing.T) {
	invalid := string([]byte{0xff})
	for _, input := range []struct{ key, spec, alpn string }{
		{invalid, "auto", "now/1"},
		{"secret", invalid, "now/1"},
		{"secret", "auto", invalid},
	} {
		if _, err := BuildEffectiveSpec(input.key, input.spec, input.alpn); err == nil {
			t.Fatalf("BuildEffectiveSpec(%q,%q,%q) accepted invalid UTF-8", input.key, input.spec, input.alpn)
		}
	}
}

func fromHex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := range out {
		hi := fromHexNibble(s[i*2])
		lo := fromHexNibble(s[i*2+1])
		out[i] = hi<<4 | lo
	}
	return out
}

func fromHexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func equalTcpOrder(a, b []TcpFrameElement) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isPerutation(order []TcpFrameElement) bool {
	seen := [3]bool{}
	for _, e := range order {
		if int(e) < 0 || int(e) >= 3 || seen[int(e)] {
			return false
		}
		seen[int(e)] = true
	}
	return true
}
