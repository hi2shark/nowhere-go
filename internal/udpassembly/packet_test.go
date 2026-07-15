package udpassembly

import (
	"bytes"
	"errors"
	"testing"

	"github.com/hi2shark/nowhere-go/wire"
)

func fragment(packetID uint32, id, count uint8, total uint16, payload []byte) wire.UDPFragment {
	return wire.UDPFragment{
		PacketID:      packetID,
		FragmentID:    id,
		FragmentCount: count,
		TotalLen:      total,
		Payload:       payload,
	}
}

func TestAssemblyOutOfOrder(t *testing.T) {
	p, _, err := NewPacket(fragment(1, 2, 3, 6, []byte("ef")))
	if err != nil {
		t.Fatalf("NewPacket: %v", err)
	}
	if _, err := p.Push(fragment(1, 0, 3, 6, []byte("ab"))); err != nil {
		t.Fatalf("Push 0: %v", err)
	}
	if _, err := p.Push(fragment(1, 1, 3, 6, []byte("cd"))); err != nil {
		t.Fatalf("Push 1: %v", err)
	}
	if !p.Complete() {
		t.Fatal("packet not complete")
	}
	got, err := p.Assemble()
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if !bytes.Equal(got, []byte("abcdef")) {
		t.Fatalf("assembled = %q, want abcdef", got)
	}
}

func TestAssemblyIdenticalDuplicateIsIdempotent(t *testing.T) {
	p, _, err := NewPacket(fragment(1, 0, 2, 4, []byte("ab")))
	if err != nil {
		t.Fatalf("NewPacket: %v", err)
	}
	res, err := p.Push(fragment(1, 0, 2, 4, []byte("ab")))
	if err != nil {
		t.Fatalf("Push identical: %v", err)
	}
	if !res.Duplicate || res.AddedBytes != 0 {
		t.Fatalf("duplicate result = %+v", res)
	}
	if _, err := p.Push(fragment(1, 1, 2, 4, []byte("cd"))); err != nil {
		t.Fatalf("Push final: %v", err)
	}
	got, err := p.Assemble()
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if !bytes.Equal(got, []byte("abcd")) {
		t.Fatalf("assembled = %q, want abcd", got)
	}
}

func TestAssemblyDuplicateCheckedBeforeLengthConflict(t *testing.T) {
	t.Run("identical", func(t *testing.T) {
		p, _, err := NewPacket(fragment(1, 0, 2, 3, []byte("ab")))
		if err != nil {
			t.Fatalf("NewPacket: %v", err)
		}
		result, err := p.Push(fragment(1, 0, 2, 3, []byte("ab")))
		if err != nil {
			t.Fatalf("Push identical: %v", err)
		}
		if !result.Duplicate || result.AddedBytes != 0 {
			t.Fatalf("duplicate result = %+v", result)
		}
		if _, err := p.Push(fragment(1, 1, 2, 3, []byte("c"))); err != nil {
			t.Fatalf("Push final: %v", err)
		}
		got, err := p.Assemble()
		if err != nil {
			t.Fatalf("Assemble: %v", err)
		}
		if !bytes.Equal(got, []byte("abc")) {
			t.Fatalf("assembled = %q, want abc", got)
		}
	})

	t.Run("conflicting", func(t *testing.T) {
		p, _, err := NewPacket(fragment(1, 0, 2, 3, []byte("ab")))
		if err != nil {
			t.Fatalf("NewPacket: %v", err)
		}
		if _, err := p.Push(fragment(1, 0, 2, 3, []byte("xy"))); !errors.Is(err, ErrDuplicateConflict) {
			t.Fatalf("Push conflicting error = %v, want ErrDuplicateConflict", err)
		}
	})
}

func TestAssemblyConflictingDuplicateFails(t *testing.T) {
	p, _, err := NewPacket(fragment(1, 0, 2, 4, []byte("ab")))
	if err != nil {
		t.Fatalf("NewPacket: %v", err)
	}
	if _, err := p.Push(fragment(1, 0, 2, 4, []byte("xy"))); err == nil {
		t.Fatal("accepted conflicting duplicate")
	}
}

func TestAssemblyMetadataConflictFails(t *testing.T) {
	p, _, err := NewPacket(fragment(1, 0, 2, 4, []byte("ab")))
	if err != nil {
		t.Fatalf("NewPacket: %v", err)
	}
	if _, err := p.Push(fragment(2, 1, 2, 4, []byte("cd"))); err == nil {
		t.Fatal("accepted different packet id")
	}
	if _, err := p.Push(fragment(1, 1, 3, 4, []byte("cd"))); err == nil {
		t.Fatal("accepted different fragment count")
	}
	if _, err := p.Push(fragment(1, 1, 2, 5, []byte("cd"))); err == nil {
		t.Fatal("accepted different total length")
	}
}

func TestAssemblyLengthConflictFails(t *testing.T) {
	p, _, err := NewPacket(fragment(1, 0, 2, 4, []byte("ab")))
	if err != nil {
		t.Fatalf("NewPacket: %v", err)
	}
	if _, err := p.Push(fragment(1, 1, 2, 4, []byte("cdef"))); err == nil {
		t.Fatal("accepted fragment exceeding total length")
	}
	p2, _, _ := NewPacket(fragment(1, 0, 1, 2, []byte("ab")))
	if _, err := p2.Push(fragment(1, 1, 2, 4, []byte("cd"))); err == nil {
		t.Fatal("accepted fragment with index >= count")
	}
}

func TestAssemblyEmptyPacketCompletes(t *testing.T) {
	p, res, err := NewPacket(fragment(1, 0, 1, 0, []byte{}))
	if err != nil {
		t.Fatalf("NewPacket: %v", err)
	}
	if !res.Complete {
		t.Fatal("empty packet not complete on first fragment")
	}
	if !p.Complete() {
		t.Fatal("Complete false")
	}
	got, err := p.Assemble()
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("assembled = %q, want empty", got)
	}
}

func TestAssemblyIncompleteCannotAssemble(t *testing.T) {
	p, _, err := NewPacket(fragment(1, 0, 2, 4, []byte("ab")))
	if err != nil {
		t.Fatalf("NewPacket: %v", err)
	}
	if p.Complete() {
		t.Fatal("Complete true before all fragments")
	}
	if _, err := p.Assemble(); err == nil {
		t.Fatal("Assemble succeeded on incomplete packet")
	}
}

func TestNewPacketRejectsZeroIDs(t *testing.T) {
	if _, _, err := NewPacket(fragment(0, 0, 1, 0, []byte{})); err == nil {
		t.Fatal("accepted zero packet id")
	}
	if _, _, err := NewPacket(fragment(1, 0, 0, 0, []byte{})); err == nil {
		t.Fatal("accepted zero fragment count")
	}
	if _, _, err := NewPacket(fragment(1, 1, 1, 0, []byte{})); err == nil {
		t.Fatal("accepted fragment id >= count")
	}
}
