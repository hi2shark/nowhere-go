package tests_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/hi2shark/nowhere-go/bundle"
	"github.com/hi2shark/nowhere-go/carrier"
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
	frame, err := wire.WriteUOTPacketFrame(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, consumed, err := wire.ReadUOTPacketFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(frame) || string(got) != string(payload) {
		t.Fatalf("uot round-trip failed: consumed=%d got=%q", consumed, got)
	}
	setup, err := wire.EncodeUOTSetupTarget("1.2.3.4:53")
	if err != nil {
		t.Fatal(err)
	}
	target, err := wire.ReadUOTSetupTarget(bytesReader(setup))
	if err != nil {
		t.Fatal(err)
	}
	if target != "1.2.3.4:53" {
		t.Fatalf("target=%q", target)
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
func (q *recordingQuic) OpenTCP(context.Context, string) (net.Conn, error) {
	return nil, errors.New("stub")
}
func (q *recordingQuic) OpenFlowStream(context.Context, string, wire.FlowHeader) (net.Conn, error) {
	return nil, errors.New("stub")
}
func (q *recordingQuic) OpenUDP(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("stub")
}
func (q *recordingQuic) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return nil, errors.New("stub")
}
func (q *recordingQuic) InvalidateSession(carrier.QuicSession) {}
func (q *recordingQuic) Close()                                {}

func bytesReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
