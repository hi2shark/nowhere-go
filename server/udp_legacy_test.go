package server

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

type recordingQuicConn struct {
	fakeQuicConn
	sent chan []byte
}

func newRecordingQuicConn() *recordingQuicConn {
	return &recordingQuicConn{sent: make(chan []byte, 32)}
}

func (c *recordingQuicConn) SendDatagram(data []byte) error {
	frame := append([]byte(nil), data...)
	c.sent <- frame
	return nil
}

type packetRoute struct {
	conn   net.PacketConn
	target string
}

func newUDPTestSession(t *testing.T, limits Limits, routes chan<- packetRoute) (*portalSession, *recordingQuicConn) {
	t.Helper()
	return newUDPTestSessionWithOptions(t, ConfigOptions{Password: "secret", Limits: limits}, routes)
}

func newUDPTestSessionWithOptions(t *testing.T, options ConfigOptions, routes chan<- packetRoute) (*portalSession, *recordingQuicConn) {
	t.Helper()
	config, err := NewConfig(options)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{
		Config: config,
		Upstream: upstreamFuncs{packet: func(_ context.Context, conn net.PacketConn, _ net.Addr, target string) error {
			routes <- packetRoute{conn: conn, target: target}
			return nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	conn := newRecordingQuicConn()
	session := newPortalSession(wire.SessionID{1}, conn, handler, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234})
	t.Cleanup(func() {
		session.Close()
		_ = handler.Close()
	})
	return session, conn
}

func encodeLegacyFrame(t *testing.T, session *portalSession, frameType uint8, flowID uint64, target string, payload []byte) []byte {
	t.Helper()
	frame, err := wire.EncodeUDPDatagram(frameType, flowID, target, payload, session.Handler.config.spec)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func awaitPacketRoute(t *testing.T, routes <-chan packetRoute) packetRoute {
	t.Helper()
	select {
	case route := <-routes:
		return route
	case <-time.After(time.Second):
		t.Fatal("packet flow was not routed upstream")
		return packetRoute{}
	}
}

func readPacket(t *testing.T, conn net.PacketConn) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer[:n]...)
}

func TestLegacyUDPRequestRoutesToUpstream(t *testing.T) {
	routes := make(chan packetRoute, 1)
	session, _ := newUDPTestSession(t, Limits{}, routes)

	const target = "request.example:53"
	payload := []byte("legacy-request")
	session.handleDatagram(context.Background(), encodeLegacyFrame(t, session, wire.UDPTypeRequest, 17, target, payload))

	route := awaitPacketRoute(t, routes)
	if route.target != target {
		t.Fatalf("target = %q, want %q", route.target, target)
	}
	if got := readPacket(t, route.conn); string(got) != string(payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	_ = route.conn.Close()
}

func TestLegacyUDPResponseUsesDerivedOrder(t *testing.T) {
	routes := make(chan packetRoute, 1)
	session, conn := newUDPTestSession(t, Limits{}, routes)

	const (
		flowID = uint64(23)
		target = "response.example:53"
	)
	requestPayload := []byte("request")
	responsePayload := []byte("response")
	session.handleDatagram(context.Background(), encodeLegacyFrame(t, session, wire.UDPTypeRequest, flowID, target, requestPayload))

	route := awaitPacketRoute(t, routes)
	if got := readPacket(t, route.conn); string(got) != string(requestPayload) {
		t.Fatalf("request payload = %q, want %q", got, requestPayload)
	}
	if n, err := route.conn.WriteTo(responsePayload, nil); err != nil || n != len(responsePayload) {
		t.Fatalf("WriteTo = (%d, %v), want (%d, nil)", n, err, len(responsePayload))
	}

	select {
	case frame := <-conn.sent:
		message, err := wire.DecodeUDPDatagram(frame, session.Handler.config.spec)
		if err != nil {
			t.Fatalf("DecodeUDPDatagram: %v", err)
		}
		if message.Type != wire.UDPTypeResponse {
			t.Fatalf("response type = %d, want %d", message.Type, wire.UDPTypeResponse)
		}
		if message.FlowID != flowID || message.Target != target || string(message.Payload) != string(responsePayload) {
			t.Fatalf("response = flow %d target %q payload %q", message.FlowID, message.Target, message.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("legacy response was not sent")
	}
	_ = route.conn.Close()
}

func TestLegacyUDPCloseUsesExactFlowAndTarget(t *testing.T) {
	routes := make(chan packetRoute, 2)
	session, _ := newUDPTestSession(t, Limits{}, routes)

	const flowID = uint64(31)
	const targetA = "a.example:53"
	const targetB = "b.example:53"
	session.handleDatagram(context.Background(), encodeLegacyFrame(t, session, wire.UDPTypeRequest, flowID, targetA, []byte("a1")))
	session.handleDatagram(context.Background(), encodeLegacyFrame(t, session, wire.UDPTypeRequest, flowID, targetB, []byte("b1")))

	flows := map[string]net.PacketConn{}
	for len(flows) < 2 {
		route := awaitPacketRoute(t, routes)
		flows[route.target] = route.conn
	}
	if got := readPacket(t, flows[targetA]); string(got) != "a1" {
		t.Fatalf("target A payload = %q", got)
	}
	if got := readPacket(t, flows[targetB]); string(got) != "b1" {
		t.Fatalf("target B payload = %q", got)
	}

	session.handleDatagram(context.Background(), encodeLegacyFrame(t, session, wire.UDPTypeClose, flowID, targetA, nil))
	if err := flows[targetA].SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := flows[targetA].ReadFrom(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("closed target ReadFrom = %v, want EOF", err)
	}

	session.handleDatagram(context.Background(), encodeLegacyFrame(t, session, wire.UDPTypeRequest, flowID, targetB, []byte("b2")))
	if got := readPacket(t, flows[targetB]); string(got) != "b2" {
		t.Fatalf("remaining target payload = %q, want b2", got)
	}
	_ = flows[targetB].Close()
}

func TestLegacyUDPSameFlowIDDifferentTargetsAreIndependent(t *testing.T) {
	routes := make(chan packetRoute, 2)
	session, _ := newUDPTestSession(t, Limits{}, routes)

	const flowID = uint64(41)
	targets := []string{"first.example:53", "second.example:53"}
	for index, target := range targets {
		payload := []byte{byte('a' + index)}
		session.handleDatagram(context.Background(), encodeLegacyFrame(t, session, wire.UDPTypeRequest, flowID, target, payload))
	}

	flows := make(map[string]net.PacketConn, len(targets))
	for len(flows) < len(targets) {
		route := awaitPacketRoute(t, routes)
		flows[route.target] = route.conn
	}
	for index, target := range targets {
		want := []byte{byte('a' + index)}
		if got := readPacket(t, flows[target]); string(got) != string(want) {
			t.Fatalf("initial payload for %q = %q, want %q", target, got, want)
		}
	}

	for index, target := range targets {
		payload := []byte{byte('x' + index)}
		session.handleDatagram(context.Background(), encodeLegacyFrame(t, session, wire.UDPTypeRequest, flowID, target, payload))
	}
	for index, target := range targets {
		want := []byte{byte('x' + index)}
		if got := readPacket(t, flows[target]); string(got) != string(want) {
			t.Fatalf("follow-up payload for %q = %q, want %q", target, got, want)
		}
		_ = flows[target].Close()
	}
}

func TestLegacyUDPSessionCloseClosesEveryFlow(t *testing.T) {
	routes := make(chan packetRoute, 2)
	session, _ := newUDPTestSession(t, Limits{}, routes)

	targets := []string{"close-a.example:53", "close-b.example:53"}
	for index, target := range targets {
		session.handleDatagram(context.Background(), encodeLegacyFrame(t, session, wire.UDPTypeRequest, uint64(51+index), target, []byte(target)))
	}
	flows := make([]net.PacketConn, 0, len(targets))
	for len(flows) < len(targets) {
		route := awaitPacketRoute(t, routes)
		_ = readPacket(t, route.conn)
		flows = append(flows, route.conn)
	}

	session.Close()
	for index, flow := range flows {
		if err := flow.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := flow.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("flow %d ReadFrom after session close = %v, want net.ErrClosed", index, err)
		}
	}
}
