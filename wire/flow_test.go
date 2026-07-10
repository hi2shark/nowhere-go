package wire

import (
	"bytes"
	"errors"
	"testing"
)

// Pins protocol.md §8.3 layout: Attach/42/Udp/Tcp/Udp.
func TestFlowHeaderWireFormat(t *testing.T) {
	header := FlowHeader{
		Role:     FlowRoleAttach,
		FlowID:   42,
		Kind:     FlowKindUDP,
		Uplink:   CarrierTCP,
		Downlink: CarrierUDP,
	}
	got, err := WriteFlowHeader(header)
	if err != nil {
		t.Fatalf("WriteFlowHeader: %v", err)
	}
	want := [FlowHeaderLen]byte{0xf1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 42, 2, 1, 2}
	if got != want {
		t.Fatalf("wire bytes mismatch\n got %x\nwant %x", got, want)
	}

	decoded, err := ReadFlowHeader(bytes.NewReader(got[:]))
	if err != nil {
		t.Fatalf("ReadFlowHeader: %v", err)
	}
	if decoded != header {
		t.Fatalf("round-trip mismatch: got %+v want %+v", decoded, header)
	}
}

func TestFlowHeaderRoundTrip(t *testing.T) {
	roles := []FlowRole{FlowRoleOpen, FlowRoleAttach}
	kinds := []FlowKind{FlowKindTCP, FlowKindUDP}
	carriers := []Carrier{CarrierTCP, CarrierUDP}
	for _, role := range roles {
		for _, kind := range kinds {
			for _, up := range carriers {
				for _, down := range carriers {
					name := carrierName(up) + "/" + carrierName(down)
					h := FlowHeader{Role: role, FlowID: 0xdeadbeef, Kind: kind, Uplink: up, Downlink: down}
					buf, err := WriteFlowHeader(h)
					if up == down {
						if err == nil {
							t.Fatalf("WriteFlowHeader accepted symmetric %s", name)
						}
						continue
					}
					if err != nil {
						t.Fatalf("WriteFlowHeader %s: %v", name, err)
					}
					got, err := ReadFlowHeader(bytes.NewReader(buf[:]))
					if err != nil {
						t.Fatalf("ReadFlowHeader %s: %v", name, err)
					}
					if got != h {
						t.Fatalf("%s round-trip mismatch: got %+v want %+v", name, got, h)
					}
				}
			}
		}
	}
}

func TestFlowHeaderRejects(t *testing.T) {
	good := FlowHeader{Role: FlowRoleOpen, FlowID: 1, Kind: FlowKindTCP, Uplink: CarrierTCP, Downlink: CarrierUDP}
	if _, err := WriteFlowHeader(FlowHeader{Role: good.Role, FlowID: 0, Kind: good.Kind, Uplink: good.Uplink, Downlink: good.Downlink}); err == nil {
		t.Fatalf("WriteFlowHeader accepted zero flow id")
	}
	if _, err := WriteFlowHeader(FlowHeader{Role: FlowRole(9), FlowID: 1, Kind: good.Kind, Uplink: good.Uplink, Downlink: good.Downlink}); err == nil {
		t.Fatalf("WriteFlowHeader accepted bad role")
	}
	if _, err := WriteFlowHeader(FlowHeader{Role: good.Role, FlowID: 1, Kind: FlowKind(7), Uplink: good.Uplink, Downlink: good.Downlink}); err == nil {
		t.Fatalf("WriteFlowHeader accepted bad kind")
	}
	if _, err := WriteFlowHeader(FlowHeader{Role: good.Role, FlowID: 1, Kind: good.Kind, Uplink: Carrier(8), Downlink: good.Downlink}); err == nil {
		t.Fatalf("WriteFlowHeader accepted bad uplink")
	}
	// Bad magic in wire.
	buf, _ := WriteFlowHeader(good)
	buf[0] ^= 0xff
	if _, err := ReadFlowHeader(bytes.NewReader(buf[:])); !errors.Is(err, ErrInvalidFlowHeader) {
		t.Fatalf("ReadFlowHeader accepted bad magic: %v", err)
	}
	// Truncated header.
	buf2, _ := WriteFlowHeader(good)
	if _, err := ReadFlowHeader(bytes.NewReader(buf2[:5])); err == nil {
		t.Fatalf("ReadFlowHeader accepted truncated header")
	}
}

func carrierName(c Carrier) string {
	switch c {
	case CarrierTCP:
		return "tcp"
	case CarrierUDP:
		return "udp"
	}
	return "?"
}
