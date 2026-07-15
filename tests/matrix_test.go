package tests_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/hi2shark/nowhere-go/bundle"
	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

// Fake dialers/backends only; cancel races covered in bundle tests.
func TestMatrixBundleSelectors(t *testing.T) {
	spec, err := wire.BuildEffectiveSpec("secret", "auto", "now/1")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		up      wire.Carrier
		down    wire.Carrier
		wantAsy bool
		needQ   bool
	}{
		{"tcp/tcp", wire.CarrierTCP, wire.CarrierTCP, false, false},
		{"tcp/udp", wire.CarrierTCP, wire.CarrierUDP, true, true},
		{"udp/tcp", wire.CarrierUDP, wire.CarrierTCP, true, true},
		{"udp/udp", wire.CarrierUDP, wire.CarrierUDP, false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tcpConfig := mustTCPConfig(t, spec)
			cfg := bundle.BundleOptions{
				TCP:      tcpConfig,
				PoolSize: 0,
				Up:       tc.up,
				Down:     tc.down,
			}
			if tc.needQ {
				cfg.QUIC = &recordingQuic{}
			}
			b, err := bundle.NewCarrierBundle(cfg)
			if err != nil {
				t.Fatalf("NewCarrierBundle: %v", err)
			}
			defer b.Close()

			if b.Asymmetric() != tc.wantAsy {
				t.Fatalf("Asymmetric=%v want %v", b.Asymmetric(), tc.wantAsy)
			}
			sid, err := b.SessionID()
			if err != nil {
				t.Fatal(err)
			}
			if sid == (wire.SessionID{}) {
				t.Fatal("zero session id")
			}
			if tc.needQ {
				q := cfg.QUIC.(*recordingQuic)
				if q.id != sid {
					t.Fatalf("quic session id not pinned")
				}
			}
		})
	}
}

func TestMatrixRejectsUDPWithoutQuic(t *testing.T) {
	spec, err := wire.BuildEffectiveSpec("secret", "auto", "now/1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = bundle.NewCarrierBundle(bundle.BundleOptions{
		TCP: mustTCPConfig(t, spec),
		Up:  wire.CarrierTCP, Down: wire.CarrierUDP,
	})
	if err == nil {
		t.Fatal("expected error for udp without QuicBackend")
	}
}

func mustTCPConfig(t *testing.T, spec *wire.EffectiveSpec) *tcptls.Config {
	t.Helper()
	config, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address: "127.0.0.1:9", Spec: spec, Key: "secret",
		Dialer: failingDialer{}, TLSDialer: plainTLS{},
	})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	return config
}

func TestMatrixUoTFramingRoundTrip(t *testing.T) {
	payload := []byte("hello-uot")
	frame, err := wire.EncodeUOTFrame(wire.UOTFrame{Kind: wire.UOTFrameData, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	got, err := wire.ReadUOTFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != wire.UOTFrameData || string(got.Payload) != string(payload) {
		t.Fatalf("uot round-trip failed: kind=%d got=%q", got.Kind, got.Payload)
	}

	// Control frames round-trip as well.
	ready, err := wire.EncodeUOTFrame(wire.UOTFrame{Kind: wire.UOTFrameReady})
	if err != nil {
		t.Fatal(err)
	}
	readyFrame, err := wire.ReadUOTFrame(bytes.NewReader(ready))
	if err != nil {
		t.Fatal(err)
	}
	if readyFrame.Kind != wire.UOTFrameReady || len(readyFrame.Payload) != 0 {
		t.Fatalf("ready frame round-trip failed: kind=%d payload=%q", readyFrame.Kind, readyFrame.Payload)
	}
}

func TestMatrixFlowHeaderRequiresAsymmetricCarriers(t *testing.T) {
	_, err := wire.WriteFlowHeader(wire.FlowHeader{
		Role: wire.FlowRoleOpen, FlowID: 1, Kind: wire.FlowKindTCP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierTCP,
	})
	if err == nil {
		t.Fatal("expected reject for symmetric flow header")
	}
	hdr, err := wire.WriteFlowHeader(wire.FlowHeader{
		Role: wire.FlowRoleOpen, FlowID: 7, Kind: wire.FlowKindUDP,
		Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP,
	})
	if err != nil {
		t.Fatal(err)
	}
	if hdr[0] != wire.FlowFrameMagic || len(hdr) != wire.FlowHeaderLen {
		t.Fatalf("bad header %#v", hdr)
	}
}

type failingDialer struct{}

func (failingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("dial disabled")
}

type recordingQuic struct{ id wire.SessionID }

func (q *recordingQuic) SetSessionID(id wire.SessionID) { q.id = id }
func (q *recordingQuic) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return nil, errors.New("stub")
}
func (q *recordingQuic) InvalidateSession(carrier.QuicSession) {}
func (q *recordingQuic) Close() error                          { return nil }

var _ quic.Backend = (*recordingQuic)(nil)
