package bundle

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestTCPUplinkUDPSetupMatchesRustOracle(t *testing.T) {
	const target = "example.com:53"
	for _, tc := range []struct {
		name string
		down wire.Carrier
	}{
		{name: "tcp-tcp", down: wire.CarrierTCP},
		{name: "tcp-udp", down: wire.CarrierUDP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := mustNowhereSpec(t)
			readyGate := make(chan struct{})
			var readyOnce sync.Once
			t.Cleanup(func() { readyOnce.Do(func() { close(readyGate) }) })

			tcpSetups := make(chan udpSetupRecord, 1)
			uplinkFrames := make(chan uotFrameResult, 1)
			tcpDialer := &rustUOTOracleTCPDialer{
				key: "k", spec: spec, selectedDownlink: tc.down == wire.CarrierTCP,
				readyGate: readyGate, setups: tcpSetups, uplinkFrames: uplinkFrames,
			}
			t.Cleanup(tcpDialer.Close)

			tcpConfig, err := tcptls.NewConfig(tcptls.TCPOptions{
				Address: "127.0.0.1:1", Spec: spec, Key: "k", Dialer: tcpDialer, TLSDialer: passthroughTLSDialer{},
			})
			if err != nil {
				t.Fatalf("NewConfig: %v", err)
			}

			var (
				quicBackend carrier.QuicBackend
				quicSetups  chan udpSetupRecord
			)
			if tc.down == wire.CarrierUDP {
				quicSetups = make(chan udpSetupRecord, 1)
				prepared := &rustUOTOraclePreparedStream{
					spec: spec, readyGate: readyGate, setups: quicSetups,
				}
				quicBackend = &rustUOTOracleQUICBackend{prepared: prepared}
			}

			bundle, err := NewCarrierBundle(BundleOptions{
				QUIC: quicBackend, TCP: tcpConfig, Up: wire.CarrierTCP, Down: tc.down,
			})
			if err != nil {
				t.Fatalf("NewCarrierBundle: %v", err)
			}
			t.Cleanup(bundle.Close)

			type openResult struct {
				pc  net.PacketConn
				err error
			}
			opened := make(chan openResult, 1)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			go func() {
				pc, err := bundle.OpenUDP(ctx, target)
				opened <- openResult{pc: pc, err: err}
			}()

			tcpSetup := receiveUDPSetupRecord(t, tcpSetups)
			wantRole := wire.FlowRoleDuplex
			if tc.down == wire.CarrierUDP {
				wantRole = wire.FlowRoleOpen
			}
			if tcpSetup.header.Role != wantRole || tcpSetup.header.Kind != wire.FlowKindUDP ||
				tcpSetup.header.Uplink != wire.CarrierTCP || tcpSetup.header.Downlink != tc.down {
				t.Fatalf("TCP setup header = %+v, want role=%d UDP tcp->%d", tcpSetup.header, wantRole, tc.down)
			}
			if tcpSetup.target != target {
				t.Fatalf("TCP setup target = %q, want %q", tcpSetup.target, target)
			}

			if tc.down == wire.CarrierUDP {
				quicSetup := receiveUDPSetupRecord(t, quicSetups)
				if quicSetup.header.Role != wire.FlowRoleAttach || quicSetup.header.Kind != wire.FlowKindUDP ||
					quicSetup.header.Uplink != wire.CarrierTCP || quicSetup.header.Downlink != wire.CarrierUDP {
					t.Fatalf("QUIC setup header = %+v, want UDP ATTACH tcp->udp", quicSetup.header)
				}
				if quicSetup.target != "" {
					t.Fatalf("QUIC ATTACH target = %q, want empty", quicSetup.target)
				}
				if !quicSetup.finishWrite {
					t.Fatal("QUIC ATTACH did not finish its write side")
				}
				if quicSetup.header.FlowID != tcpSetup.header.FlowID {
					t.Fatalf("flow ids = TCP %d QUIC %d, want equal", tcpSetup.header.FlowID, quicSetup.header.FlowID)
				}
			}

			select {
			case result := <-opened:
				if result.pc != nil {
					_ = result.pc.Close()
				}
				t.Fatalf("OpenUDP returned before selected downlink READY: %v", result.err)
			case <-time.After(20 * time.Millisecond):
			}

			readyOnce.Do(func() { close(readyGate) })
			var pc net.PacketConn
			select {
			case result := <-opened:
				if result.err != nil {
					t.Fatalf("OpenUDP after selected downlink READY: %v", result.err)
				}
				if result.pc == nil {
					t.Fatal("OpenUDP returned nil PacketConn")
				}
				pc = result.pc
			case <-time.After(250 * time.Millisecond):
				cancel()
				tcpDialer.Close()
				t.Fatal("OpenUDP did not return after selected downlink READY")
			}
			defer pc.Close()

			if tc.down == wire.CarrierUDP {
				select {
				case result := <-uplinkFrames:
					if result.err != nil {
						t.Fatalf("read TCP uplink frame before payload: %v", result.err)
					}
					t.Fatalf("first TCP uplink frame before payload = kind %d payload %x, want no frame", result.frame.Kind, result.frame.Payload)
				case <-time.After(20 * time.Millisecond):
				}
			}

			payload := []byte("ping")
			if n, err := pc.WriteTo(payload, nil); err != nil || n != len(payload) {
				t.Fatalf("WriteTo = (%d, %v), want (%d, nil)", n, err, len(payload))
			}
			select {
			case result := <-uplinkFrames:
				if result.err != nil {
					t.Fatalf("read first TCP uplink frame: %v", result.err)
				}
				if result.frame.Kind != wire.UOTFrameData || !bytes.Equal(result.frame.Payload, payload) {
					t.Fatalf("first TCP uplink frame = kind %d payload %x, want DATA %x", result.frame.Kind, result.frame.Payload, payload)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("timed out waiting for first TCP uplink frame")
			}
		})
	}
}

type uotFrameResult struct {
	frame wire.UOTFrame
	err   error
}

type rustUOTOracleTCPDialer struct {
	key              string
	spec             *wire.EffectiveSpec
	selectedDownlink bool
	readyGate        <-chan struct{}
	setups           chan udpSetupRecord
	uplinkFrames     chan uotFrameResult

	mu    sync.Mutex
	conns []net.Conn
}

func (d *rustUOTOracleTCPDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	d.mu.Lock()
	d.conns = append(d.conns, client, server)
	d.mu.Unlock()
	go func() {
		defer server.Close()
		if _, err := wire.ReadAuthFrame(server, d.key, d.spec); err != nil {
			d.setups <- udpSetupRecord{err: err}
			return
		}
		record := readUDPSetupRecord(server, d.spec)
		d.setups <- record
		if record.err != nil {
			return
		}
		if d.selectedDownlink {
			<-d.readyGate
			if _, err := server.Write([]byte{0x02, 0x00, 0x00}); err != nil {
				d.uplinkFrames <- uotFrameResult{err: err}
				return
			}
		}
		frame, err := wire.ReadUOTFrame(server)
		d.uplinkFrames <- uotFrameResult{frame: frame, err: err}
	}()
	return client, nil
}

func (d *rustUOTOracleTCPDialer) Close() {
	d.mu.Lock()
	conns := append([]net.Conn(nil), d.conns...)
	d.conns = nil
	d.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

type rustUOTOraclePreparedStream struct {
	spec      *wire.EffectiveSpec
	readyGate <-chan struct{}
	setups    chan udpSetupRecord

	mu    sync.Mutex
	conns []net.Conn
}

func (p *rustUOTOraclePreparedStream) Commit(_ context.Context, setup []byte, finishWrite bool) (net.Conn, error) {
	record := decodeUDPSetupRecord(setup, p.spec)
	record.finishWrite = finishWrite
	p.setups <- record
	if record.err != nil {
		return nil, record.err
	}
	client, server := net.Pipe()
	p.mu.Lock()
	p.conns = append(p.conns, client, server)
	p.mu.Unlock()
	go func() {
		defer server.Close()
		<-p.readyGate
		if _, err := server.Write([]byte{0xf2, 0x01, 0x01, 0x00}); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, server)
	}()
	return client, nil
}

func (p *rustUOTOraclePreparedStream) Close() error {
	p.closeConns()
	return nil
}

func (p *rustUOTOraclePreparedStream) closeConns() {
	p.mu.Lock()
	conns := append([]net.Conn(nil), p.conns...)
	p.conns = nil
	p.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

var _ quic.PreparedStream = (*rustUOTOraclePreparedStream)(nil)

type rustUOTOracleQUICBackend struct {
	prepared *rustUOTOraclePreparedStream
}

func (*rustUOTOracleQUICBackend) SetSessionID(wire.SessionID) {}
func (b *rustUOTOracleQUICBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return &rustUOTOracleQUICSession{prepared: b.prepared}, nil
}
func (*rustUOTOracleQUICBackend) InvalidateSession(carrier.QuicSession) {}
func (b *rustUOTOracleQUICBackend) Close() error {
	b.prepared.closeConns()
	return nil
}

type rustUOTOracleQUICSession struct {
	prepared quic.PreparedStream
}

func (s *rustUOTOracleQUICSession) PrepareStream(context.Context) (quic.PreparedStream, error) {
	return s.prepared, nil
}
func (*rustUOTOracleQUICSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*rustUOTOracleQUICSession) CurrentMaxDatagramSize() int { return 1200 }
func (*rustUOTOracleQUICSession) SendDatagram([]byte) error   { return nil }
func (*rustUOTOracleQUICSession) LocalAddr() net.Addr         { return &net.UDPAddr{} }

var (
	_ quic.Backend = (*rustUOTOracleQUICBackend)(nil)
	_ quic.Session = (*rustUOTOracleQUICSession)(nil)
)
