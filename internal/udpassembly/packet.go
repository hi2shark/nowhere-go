package udpassembly

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/hi2shark/nowhere-go/wire"
)

var (
	ErrMetadataConflict  = errors.New("nowhere: fragment metadata conflict")
	ErrDuplicateConflict = errors.New("nowhere: duplicate fragment payload conflict")
	ErrLengthConflict    = errors.New("nowhere: fragment length conflict")
)

type PushResult struct {
	AddedBytes int
	Duplicate  bool
	Complete   bool
}

type Packet struct {
	packetID      uint32
	fragmentCount uint8
	totalLen      uint16
	fragments     [][]byte
	seen          []bool
	receivedBytes int
	complete      bool
}

// NewPacket creates a packet state from the first fragment and returns whether it is already complete.
func NewPacket(first wire.UDPFragment) (*Packet, PushResult, error) {
	if first.PacketID == 0 {
		return nil, PushResult{}, errors.New("nowhere: zero packet id")
	}
	if first.FragmentCount == 0 || first.FragmentID >= first.FragmentCount {
		return nil, PushResult{}, errors.New("nowhere: invalid fragment metadata")
	}
	p := &Packet{
		packetID:      first.PacketID,
		fragmentCount: first.FragmentCount,
		totalLen:      first.TotalLen,
		fragments:     make([][]byte, first.FragmentCount),
		seen:          make([]bool, first.FragmentCount),
	}
	res, err := p.Push(first)
	return p, res, err
}

// Push adds a fragment to the packet.
func (p *Packet) Push(fragment wire.UDPFragment) (PushResult, error) {
	if fragment.PacketID != p.packetID {
		return PushResult{}, fmt.Errorf("%w: packet id %d != %d", ErrMetadataConflict, fragment.PacketID, p.packetID)
	}
	if fragment.FragmentCount != p.fragmentCount || fragment.TotalLen != p.totalLen {
		return PushResult{}, fmt.Errorf("%w: fragment metadata mismatch", ErrMetadataConflict)
	}
	if fragment.FragmentID >= p.fragmentCount {
		return PushResult{}, fmt.Errorf("%w: fragment id %d >= count %d", ErrMetadataConflict, fragment.FragmentID, p.fragmentCount)
	}
	if p.seen[fragment.FragmentID] {
		if !bytes.Equal(p.fragments[fragment.FragmentID], fragment.Payload) {
			return PushResult{}, fmt.Errorf("%w: fragment %d", ErrDuplicateConflict, fragment.FragmentID)
		}
		return PushResult{Duplicate: true}, nil
	}
	if p.receivedBytes+len(fragment.Payload) > int(p.totalLen) {
		return PushResult{}, fmt.Errorf("%w: cumulative %d exceeds total %d", ErrLengthConflict, p.receivedBytes+len(fragment.Payload), p.totalLen)
	}
	p.fragments[fragment.FragmentID] = fragment.Payload
	p.seen[fragment.FragmentID] = true
	p.receivedBytes += len(fragment.Payload)
	if p.allSeen() && p.receivedBytes == int(p.totalLen) {
		p.complete = true
	}
	return PushResult{AddedBytes: len(fragment.Payload), Complete: p.complete}, nil
}

// BufferedBytes returns the total payload bytes currently buffered.
func (p *Packet) BufferedBytes() int {
	return p.receivedBytes
}

// Complete reports whether every fragment has been received and lengths match.
func (p *Packet) Complete() bool {
	return p.complete
}

// Assemble returns the full UDP payload after the packet is complete.
func (p *Packet) Assemble() ([]byte, error) {
	if !p.complete {
		return nil, errors.New("nowhere: packet incomplete")
	}
	if p.totalLen == 0 {
		return []byte{}, nil
	}
	out := make([]byte, 0, p.totalLen)
	for _, frag := range p.fragments {
		out = append(out, frag...)
	}
	return out, nil
}

func (p *Packet) allSeen() bool {
	for _, s := range p.seen {
		if !s {
			return false
		}
	}
	return true
}
