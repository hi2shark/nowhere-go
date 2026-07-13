package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

type gatedQuicStream struct {
	QuicStream
	gate <-chan struct{}
	once sync.Once
}

func (s *gatedQuicStream) Read(buffer []byte) (int, error) {
	s.once.Do(func() { <-s.gate })
	return s.QuicStream.Read(buffer)
}

type legacyAcceptancePacket struct {
	target   string
	payload  []byte
	response []byte
	err      error
}

type legacyAcceptanceClose struct {
	target string
	err    error
}

func TestServeQUICLegacyDerivedUDPAcceptance(t *testing.T) {
	const (
		flowID  = uint64(0x1020304050607080)
		targetA = "legacy-a.example:53"
		targetB = "legacy-b.example:53"
	)

	config, err := NewConfig(ConfigOptions{
		Password: "secret",
		Timeouts: Timeouts{Auth: time.Second, UDPIdle: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}

	packets := make(chan legacyAcceptancePacket, 4)
	closes := make(chan legacyAcceptanceClose, 2)
	upstream := upstreamFuncs{packet: func(_ context.Context, conn net.PacketConn, _ net.Addr, target string) error {
		defer conn.Close()

		reads := 0
		switch target {
		case targetA:
			reads = 1
		case targetB:
			reads = 2
		default:
			err := fmt.Errorf("unexpected target %q", target)
			packets <- legacyAcceptancePacket{target: target, err: err}
			return err
		}

		for index := 0; index < reads; index++ {
			if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				packets <- legacyAcceptancePacket{target: target, err: err}
				return err
			}
			buffer := make([]byte, 2048)
			n, _, err := conn.ReadFrom(buffer)
			if err != nil {
				packets <- legacyAcceptancePacket{target: target, err: err}
				return err
			}
			payload := append([]byte(nil), buffer[:n]...)
			response := append([]byte("response:"), payload...)
			written, err := conn.WriteTo(response, nil)
			packets <- legacyAcceptancePacket{
				target:   target,
				payload:  payload,
				response: response,
				err:      err,
			}
			if err != nil {
				return err
			}
			if written != len(response) {
				err := io.ErrShortWrite
				packets <- legacyAcceptancePacket{target: target, err: err}
				return err
			}
		}

		if target == targetA {
			if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				closes <- legacyAcceptanceClose{target: target, err: err}
				return err
			}
			_, _, err := conn.ReadFrom(make([]byte, 1))
			closes <- legacyAcceptanceClose{target: target, err: err}
		}
		return nil
	}}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: upstream})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	handler.randRead = func([]byte) (int, error) { return 0, errors.New("deterministic auth deadline") }

	authFrame, err := wire.MakeAuthFrameWithSession("secret", config.EffectiveSpec(), wire.SessionID{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	preAuthRequest := encodeLegacyAcceptanceFrame(t, config.EffectiveSpec(), wire.UDPTypeRequest, flowID, targetA, []byte("a1"))
	requestB1 := encodeLegacyAcceptanceFrame(t, config.EffectiveSpec(), wire.UDPTypeRequest, flowID, targetB, []byte("b1"))
	closeA := encodeLegacyAcceptanceFrame(t, config.EffectiveSpec(), wire.UDPTypeClose, flowID, targetA, nil)
	requestB2 := encodeLegacyAcceptanceFrame(t, config.EffectiveSpec(), wire.UDPTypeRequest, flowID, targetB, []byte("b2"))

	authGate := make(chan struct{})
	conn := newScriptedQuicConn()
	conn.streams <- &gatedQuicStream{
		QuicStream: &fakeQuicStream{reader: bytes.NewReader(authFrame)},
		gate:       authGate,
	}
	conn.datagrams <- preAuthRequest

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- handler.ServeQUIC(ctx, conn) }()

	waitForTestCondition(t, time.Second, func() bool {
		return conn.receiveDatagramCalls.Load() >= 2
	}, "pre-auth datagram was not received before authentication")
	close(authGate)
	waitForTestCondition(t, time.Second, func() bool {
		return conn.acceptStreamCalls.Load() >= 2
	}, "ServeQUIC did not enter the authenticated stream loop")

	expectLegacyAcceptancePacket(t, packets, targetA, []byte("a1"), []byte("response:a1"))
	expectLegacyAcceptanceResponse(t, conn, config.EffectiveSpec(), flowID, targetA, []byte("response:a1"))

	conn.datagrams <- requestB1
	expectLegacyAcceptancePacket(t, packets, targetB, []byte("b1"), []byte("response:b1"))
	expectLegacyAcceptanceResponse(t, conn, config.EffectiveSpec(), flowID, targetB, []byte("response:b1"))

	conn.datagrams <- closeA
	select {
	case result := <-closes:
		if result.target != targetA || !errors.Is(result.err, io.EOF) {
			t.Fatalf("closed flow = (%q, %v), want (%q, EOF)", result.target, result.err, targetA)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("legacy close did not close the exact flow")
	}

	select {
	case err := <-serveDone:
		t.Fatalf("ServeQUIC returned while target B should remain active: %v", err)
	default:
	}
	conn.datagrams <- requestB2
	expectLegacyAcceptancePacket(t, packets, targetB, []byte("b2"), []byte("response:b2"))
	expectLegacyAcceptanceResponse(t, conn, config.EffectiveSpec(), flowID, targetB, []byte("response:b2"))

	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("ServeQUIC after cancellation = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeQUIC did not stop after cancellation")
	}
}

func encodeLegacyAcceptanceFrame(t *testing.T, spec *wire.EffectiveSpec, frameType uint8, flowID uint64, target string, payload []byte) []byte {
	t.Helper()
	frame, err := wire.EncodeUDPDatagram(frameType, flowID, target, payload, spec)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func expectLegacyAcceptancePacket(t *testing.T, packets <-chan legacyAcceptancePacket, target string, payload, response []byte) {
	t.Helper()
	select {
	case packet := <-packets:
		if packet.err != nil {
			t.Fatalf("upstream packet for %q failed: %v", packet.target, packet.err)
		}
		if packet.target != target || !bytes.Equal(packet.payload, payload) || !bytes.Equal(packet.response, response) {
			t.Fatalf("upstream packet = target %q payload %q response %q, want target %q payload %q response %q", packet.target, packet.payload, packet.response, target, payload, response)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("upstream did not receive payload for %q", target)
	}
}

func expectLegacyAcceptanceResponse(t *testing.T, conn *scriptedQuicConn, spec *wire.EffectiveSpec, flowID uint64, target string, payload []byte) {
	t.Helper()
	select {
	case frame := <-conn.sent:
		message, err := wire.DecodeUDPDatagram(frame, spec)
		if err != nil {
			t.Fatalf("DecodeUDPDatagram: %v", err)
		}
		if message.Type != wire.UDPTypeResponse || message.FlowID != flowID || message.Target != target || !bytes.Equal(message.Payload, payload) {
			t.Fatalf("response = type %d flow %d target %q payload %q, want type %d flow %d target %q payload %q", message.Type, message.FlowID, message.Target, message.Payload, wire.UDPTypeResponse, flowID, target, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("legacy response for %q was not sent", target)
	}
}
