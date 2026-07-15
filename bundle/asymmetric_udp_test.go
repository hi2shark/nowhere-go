package bundle

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

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestUDPQUICUplinkTCPDownlinkCommitsAttachBeforeWaitingForReady(t *testing.T) {
	const target = "example.com:443"

	spec := mustNowhereSpec(t)
	quicRecords := make(chan udpSetupRecord, 1)
	tcpRecords := make(chan udpSetupRecord, 1)
	quicReadStarted := make(chan struct{})
	releaseQUICRead := make(chan struct{})
	releaseTCPReady := make(chan struct{})
	var releaseQUICReadOnce sync.Once
	var releaseTCPReadyOnce sync.Once
	t.Cleanup(func() {
		releaseQUICReadOnce.Do(func() { close(releaseQUICRead) })
		releaseTCPReadyOnce.Do(func() { close(releaseTCPReady) })
	})

	quicControl := &udpSetupControlConn{
		readStarted: quicReadStarted,
		releaseRead: releaseQUICRead,
	}
	quicBackend := &udpSetupQUICBackend{prep: &udpSetupPreparedStream{
		spec: spec, records: quicRecords, control: quicControl,
	}}
	tcpDialer := &udpSetupTCPDialer{
		key: "k", spec: spec, records: tcpRecords, releaseReady: releaseTCPReady,
	}
	tcpConfig, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address: "127.0.0.1:1", Spec: spec, Key: "k", Dialer: tcpDialer, TLSDialer: passthroughTLSDialer{},
	})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	bundle, err := NewCarrierBundle(BundleOptions{
		QUIC: quicBackend, TCP: tcpConfig, Up: wire.CarrierUDP, Down: wire.CarrierTCP,
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	go func() {
		pc, err := bundle.OpenUDP(ctx, target)
		opened <- openResult{pc: pc, err: err}
	}()

	quicRecord := receiveUDPSetupRecord(t, quicRecords)
	if quicRecord.header.Role != wire.FlowRoleOpen || quicRecord.header.Kind != wire.FlowKindUDP ||
		quicRecord.header.Uplink != wire.CarrierUDP || quicRecord.header.Downlink != wire.CarrierTCP {
		t.Fatalf("QUIC setup header = %+v, want UDP OPEN udp->tcp", quicRecord.header)
	}
	if quicRecord.target != target {
		t.Fatalf("QUIC target = %q, want %q", quicRecord.target, target)
	}
	if !quicRecord.finishWrite {
		t.Fatal("QUIC OPEN did not finish its write side")
	}

	var tcpRecord udpSetupRecord
	select {
	case <-quicReadStarted:
		t.Fatal("QUIC OPEN control was read before TCP ATTACH was committed")
	case tcpRecord = <-tcpRecords:
		if tcpRecord.err != nil {
			t.Fatalf("TCP setup: %v", tcpRecord.err)
		}
	case result := <-opened:
		if result.pc != nil {
			_ = result.pc.Close()
		}
		t.Fatalf("OpenUDP returned before TCP ATTACH: %v", result.err)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for TCP ATTACH")
	}

	if tcpRecord.header.Role != wire.FlowRoleAttach || tcpRecord.header.Kind != wire.FlowKindUDP ||
		tcpRecord.header.Uplink != wire.CarrierUDP || tcpRecord.header.Downlink != wire.CarrierTCP {
		t.Fatalf("TCP setup header = %+v, want UDP ATTACH udp->tcp", tcpRecord.header)
	}
	if tcpRecord.target != "" {
		t.Fatalf("TCP ATTACH target = %q, want empty", tcpRecord.target)
	}
	if tcpRecord.header.FlowID == 0 || tcpRecord.header.FlowID != quicRecord.header.FlowID {
		t.Fatalf("flow ids = QUIC %d TCP %d, want same nonzero id", quicRecord.header.FlowID, tcpRecord.header.FlowID)
	}
	select {
	case <-quicReadStarted:
		t.Fatal("QUIC OPEN control was read while waiting for TCP READY")
	default:
	}
	select {
	case result := <-opened:
		if result.pc != nil {
			_ = result.pc.Close()
		}
		t.Fatalf("OpenUDP returned before TCP typed UoT READY: %v", result.err)
	case <-time.After(25 * time.Millisecond):
	}

	releaseTCPReadyOnce.Do(func() { close(releaseTCPReady) })
	select {
	case result := <-opened:
		if result.err != nil {
			t.Fatalf("OpenUDP after TCP READY: %v", result.err)
		}
		if result.pc == nil {
			t.Fatal("OpenUDP returned nil PacketConn")
		}
		_ = result.pc.Close()
	case <-time.After(500 * time.Millisecond):
		t.Fatal("OpenUDP did not return after TCP typed UoT READY")
	}
}

var errUDPSetupQUICRead = errors.New("test: QUIC OPEN control must not be read")

type udpSetupControlConn struct {
	readStarted chan struct{}
	releaseRead chan struct{}
	once        sync.Once
}

func (c *udpSetupControlConn) Read([]byte) (int, error) {
	c.once.Do(func() { close(c.readStarted) })
	<-c.releaseRead
	return 0, errUDPSetupQUICRead
}

func (c *udpSetupControlConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *udpSetupControlConn) Close() error                     { return nil }
func (c *udpSetupControlConn) LocalAddr() net.Addr              { return dummyAddr("quic-local") }
func (c *udpSetupControlConn) RemoteAddr() net.Addr             { return dummyAddr("quic-remote") }
func (c *udpSetupControlConn) SetDeadline(time.Time) error      { return nil }
func (c *udpSetupControlConn) SetReadDeadline(time.Time) error  { return nil }
func (c *udpSetupControlConn) SetWriteDeadline(time.Time) error { return nil }

type udpSetupRecord struct {
	header      wire.FlowHeader
	target      string
	finishWrite bool
	err         error
}

type udpSetupPreparedStream struct {
	spec    *wire.EffectiveSpec
	records chan udpSetupRecord
	control net.Conn
}

func (p *udpSetupPreparedStream) Commit(_ context.Context, setup []byte, finishWrite bool) (net.Conn, error) {
	record := decodeUDPSetupRecord(setup, p.spec)
	record.finishWrite = finishWrite
	p.records <- record
	if record.err != nil {
		return nil, record.err
	}
	return p.control, nil
}

func (p *udpSetupPreparedStream) Close() error { return nil }

var _ quic.PreparedStream = (*udpSetupPreparedStream)(nil)

type udpSetupQUICBackend struct {
	id   wire.SessionID
	prep quic.PreparedStream
}

func (b *udpSetupQUICBackend) SetSessionID(id wire.SessionID) { b.id = id }
func (b *udpSetupQUICBackend) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return &fakeQuicSession{prep: b.prep}, nil
}
func (b *udpSetupQUICBackend) InvalidateSession(carrier.QuicSession) {}
func (b *udpSetupQUICBackend) Close() error                          { return nil }

var _ quic.Backend = (*udpSetupQUICBackend)(nil)

type udpSetupTCPDialer struct {
	key          string
	spec         *wire.EffectiveSpec
	records      chan udpSetupRecord
	releaseReady <-chan struct{}
}

func (d *udpSetupTCPDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if _, err := wire.ReadAuthFrame(server, d.key, d.spec); err != nil {
			d.records <- udpSetupRecord{err: fmt.Errorf("read auth: %w", err)}
			return
		}
		record := readUDPSetupRecord(server, d.spec)
		d.records <- record
		if record.err != nil {
			return
		}
		<-d.releaseReady
		if err := wire.WriteUOTFrame(server, wire.UOTFrame{Kind: wire.UOTFrameReady}); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, server)
	}()
	return client, nil
}

func decodeUDPSetupRecord(setup []byte, spec *wire.EffectiveSpec) udpSetupRecord {
	reader := bytes.NewReader(setup)
	record := readUDPSetupRecord(reader, spec)
	if record.err == nil && reader.Len() != 0 {
		record.err = fmt.Errorf("unexpected trailing setup bytes: %d", reader.Len())
	}
	return record
}

func readUDPSetupRecord(reader io.Reader, spec *wire.EffectiveSpec) udpSetupRecord {
	header, err := wire.ReadFlowHeader(reader)
	if err != nil {
		return udpSetupRecord{err: fmt.Errorf("read flow header: %w", err)}
	}
	record := udpSetupRecord{header: header}
	if header.Role != wire.FlowRoleAttach {
		record.target, record.err = wire.DecodeTCPRequest(reader, spec)
		if record.err != nil {
			record.err = fmt.Errorf("read target: %w", record.err)
		}
	}
	return record
}

func receiveUDPSetupRecord(t *testing.T, records <-chan udpSetupRecord) udpSetupRecord {
	t.Helper()
	select {
	case record := <-records:
		if record.err != nil {
			t.Fatalf("flow setup: %v", record.err)
		}
		return record
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for flow setup")
		return udpSetupRecord{}
	}
}
