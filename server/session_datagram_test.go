package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/hi2shark/nowhere-go/wire"
)

func TestDatagramClassificationFallsBackFromCompactPrefixToDerived(t *testing.T) {
	routes := make(chan packetRoute, 1)
	specName, frame, target, payload := findDerivedCompactPrefixCollision(t)
	session, _ := newUDPTestSessionWithOptions(t, ConfigOptions{Password: "secret", Spec: specName}, routes)

	session.handleDatagram(context.Background(), frame)

	route := awaitPacketRoute(t, routes)
	if route.target != target {
		t.Fatalf("target = %q, want %q", route.target, target)
	}
	if got := readPacket(t, route.conn); string(got) != string(payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	_ = route.conn.Close()
}

func TestDatagramClassificationPrefersFullyValidCompact(t *testing.T) {
	routes := make(chan packetRoute, 1)
	session, _ := newUDPTestSession(t, Limits{}, routes)

	const target = "compact.example:53"
	payload := []byte("compact-payload")
	frame, err := wire.EncodeUDPOpenData(77, wire.CarrierUDP, target, payload)
	if err != nil {
		t.Fatal(err)
	}
	session.handleDatagram(context.Background(), frame)

	route := awaitPacketRoute(t, routes)
	if route.target != target {
		t.Fatalf("target = %q, want %q", route.target, target)
	}
	if _, ok := route.conn.(*compactUDPFlow); !ok {
		t.Fatalf("routed conn type = %T, want *compactUDPFlow", route.conn)
	}
	if got := readPacket(t, route.conn); string(got) != string(payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	_ = route.conn.Close()
}

func findDerivedCompactPrefixCollision(t *testing.T) (string, []byte, string, []byte) {
	t.Helper()
	payload := []byte("derived-collision")
	for specIndex := 0; specIndex < 256; specIndex++ {
		specName := fmt.Sprintf("classification-%d", specIndex)
		spec, err := wire.BuildEffectiveSpec("secret", specName, "")
		if err != nil {
			t.Fatal(err)
		}
		probe, err := wire.EncodeUDPDatagram(wire.UDPTypeRequest, 1, strings.Repeat("a", 14)+":53", payload, spec)
		if err != nil {
			t.Fatal(err)
		}
		if len(probe) < 2 || probe[1] < wire.UDPTypeOpenData || probe[1] > wire.UDPTypeCompactClose {
			continue
		}
		for hostLen := 1; hostLen <= 255; hostLen++ {
			target := strings.Repeat("a", hostLen) + ":53"
			for flowID := uint64(1); flowID <= 4096; flowID++ {
				frame, err := wire.EncodeUDPDatagram(wire.UDPTypeRequest, flowID, target, payload, spec)
				if err != nil {
					t.Fatalf("EncodeUDPDatagram(flow=%d,target_len=%d): %v", flowID, hostLen, err)
				}
				if len(frame) < 2 || frame[1] < wire.UDPTypeOpenData || frame[1] > wire.UDPTypeCompactClose {
					continue
				}
				if _, err := wire.DecodeUDPCompact(frame); err != nil {
					return specName, frame, target, payload
				}
			}
		}
	}
	t.Fatal("no valid derived-order frame with a Compact type prefix was found")
	return "", nil, "", nil
}

var _ net.PacketConn = (*compactUDPFlow)(nil)
