package bundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/quic"
	"github.com/hi2shark/nowhere-go/carrier/tcptls"
	"github.com/hi2shark/nowhere-go/wire"
)

func TestOpenTCPCancelsOtherHalfOnFailure(t *testing.T) {
	spec := mustNowhereSpec(t)
	tcpDialer := newPipeTCPDialer()
	quic := &failPrepareQuic{}
	tcpConfig, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address: "127.0.0.1:1", Spec: spec, Key: "k", Dialer: tcpDialer, TLSDialer: passthroughTLSDialer{},
	})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	bundle, err := NewCarrierBundle(BundleOptions{
		QUIC: quic, TCP: tcpConfig, Up: wire.CarrierTCP, Down: wire.CarrierUDP,
	})
	if err != nil {
		t.Fatalf("NewCarrierBundle: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := bundle.OpenTCP(ctx, "example.com:443")
	elapsed := time.Since(start)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatalf("OpenTCP succeeded; want failure")
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("OpenTCP waited %s; want fast failure after QUIC prepare errors", elapsed)
	}
	select {
	case <-tcpDialer.closed:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("prepared TCP half was not closed after QUIC prepare failed")
	}
}

func TestSplicedConnForwardsDirectionalDeadlines(t *testing.T) {
	reader := &deadlineRecorderConn{}
	writer := &deadlineRecorderConn{}
	conn := &splicedConn{
		reader: reader,
		writer: writer,
		closer: []io.Closer{reader, writer},
		remote: dummyAddr("remote"),
		local:  dummyAddr("local"),
	}

	readAt := time.Unix(10, 0)
	if err := conn.SetReadDeadline(readAt); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if got := reader.readDeadline; !got.Equal(readAt) {
		t.Fatalf("reader read deadline = %v, want %v", got, readAt)
	}
	if !writer.readDeadline.IsZero() || !writer.writeDeadline.IsZero() {
		t.Fatalf("SetReadDeadline touched writer deadlines: read=%v write=%v", writer.readDeadline, writer.writeDeadline)
	}

	writeAt := time.Unix(20, 0)
	if err := conn.SetWriteDeadline(writeAt); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if got := writer.writeDeadline; !got.Equal(writeAt) {
		t.Fatalf("writer write deadline = %v, want %v", got, writeAt)
	}
	if got := reader.readDeadline; !got.Equal(readAt) {
		t.Fatalf("SetWriteDeadline changed reader read deadline = %v, want %v", got, readAt)
	}

	fullAt := time.Unix(30, 0)
	if err := conn.SetDeadline(fullAt); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if got := reader.readDeadline; !got.Equal(fullAt) {
		t.Fatalf("reader read deadline after SetDeadline = %v, want %v", got, fullAt)
	}
	if got := writer.writeDeadline; !got.Equal(fullAt) {
		t.Fatalf("writer write deadline after SetDeadline = %v, want %v", got, fullAt)
	}
}

func TestAsymmetricPacketConnForwardsUOTDeadlines(t *testing.T) {
	uplink := &deadlineRecorderConn{}
	downlink := &deadlineRecorderConn{}
	pc := &asymmetricPacketConn{
		uplink:   &uotLaneUplink{raw: uplink},
		downlink: &uotLaneDownlink{raw: downlink},
	}

	readAt := time.Unix(40, 0)
	if err := pc.SetReadDeadline(readAt); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if got := downlink.readDeadline; !got.Equal(readAt) {
		t.Fatalf("downlink read deadline = %v, want %v", got, readAt)
	}
	if !uplink.readDeadline.IsZero() || !uplink.writeDeadline.IsZero() {
		t.Fatalf("SetReadDeadline touched uplink deadlines: read=%v write=%v", uplink.readDeadline, uplink.writeDeadline)
	}

	writeAt := time.Unix(50, 0)
	if err := pc.SetWriteDeadline(writeAt); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if got := uplink.writeDeadline; !got.Equal(writeAt) {
		t.Fatalf("uplink write deadline = %v, want %v", got, writeAt)
	}
	if got := downlink.readDeadline; !got.Equal(readAt) {
		t.Fatalf("SetWriteDeadline changed downlink read deadline = %v, want %v", got, readAt)
	}

	fullAt := time.Unix(60, 0)
	if err := pc.SetDeadline(fullAt); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if got := downlink.readDeadline; !got.Equal(fullAt) {
		t.Fatalf("downlink read deadline after SetDeadline = %v, want %v", got, fullAt)
	}
	if got := uplink.writeDeadline; !got.Equal(fullAt) {
		t.Fatalf("uplink write deadline after SetDeadline = %v, want %v", got, fullAt)
	}
}

func mustNowhereSpec(t *testing.T) *wire.EffectiveSpec {
	t.Helper()
	spec, err := wire.BuildEffectiveSpec("k", "auto", "now/1")
	if err != nil {
		t.Fatalf("BuildEffectiveSpec: %v", err)
	}
	return spec
}

type pipeTCPDialer struct {
	closed chan struct{}
	once   sync.Once
}

func newPipeTCPDialer() *pipeTCPDialer {
	return &pipeTCPDialer{closed: make(chan struct{})}
}

func (d *pipeTCPDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		buf := make([]byte, 4096)
		for {
			if _, err := c2.Read(buf); err != nil {
				d.once.Do(func() { close(d.closed) })
				return
			}
		}
	}()
	return c1, nil
}

type passthroughTLSDialer struct{}

func (passthroughTLSDialer) DialTLSConn(ctx context.Context, c net.Conn) (net.Conn, error) {
	return c, nil
}

type deadlineRecorderConn struct {
	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *deadlineRecorderConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *deadlineRecorderConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *deadlineRecorderConn) Close() error                { return nil }
func (c *deadlineRecorderConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (c *deadlineRecorderConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }
func (c *deadlineRecorderConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}
func (c *deadlineRecorderConn) SetReadDeadline(t time.Time) error  { c.readDeadline = t; return nil }
func (c *deadlineRecorderConn) SetWriteDeadline(t time.Time) error { c.writeDeadline = t; return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

// fakeQuicSession implements quic.Session for tests.
type fakeQuicSession struct {
	prep quic.PreparedStream
}

func (s *fakeQuicSession) PrepareStream(context.Context) (quic.PreparedStream, error) {
	if s.prep == nil {
		return nil, errors.New("test: no prepared stream")
	}
	return s.prep, nil
}
func (s *fakeQuicSession) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, errors.New("test: unexpected ReceiveDatagram")
}
func (s *fakeQuicSession) CurrentMaxDatagramSize() int { return 1200 }
func (s *fakeQuicSession) SendDatagram([]byte) error   { return nil }
func (s *fakeQuicSession) LocalAddr() net.Addr         { return &net.UDPAddr{} }

var _ quic.Session = (*fakeQuicSession)(nil)

type failPrepareQuic struct {
	id wire.SessionID
}

func (q *failPrepareQuic) SetSessionID(id wire.SessionID) { q.id = id }
func (q *failPrepareQuic) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return nil, errors.New("test: quic prepare failed")
}
func (q *failPrepareQuic) InvalidateSession(carrier.QuicSession) {}
func (q *failPrepareQuic) Close() error                          { return nil }

var _ quic.Backend = (*failPrepareQuic)(nil)

type recordingPreparedStream struct {
	committed  chan struct{}
	closed     chan struct{}
	failCommit bool
	once       sync.Once
}

func (p *recordingPreparedStream) Commit(context.Context, []byte, bool) (net.Conn, error) {
	if p.failCommit {
		p.once.Do(func() { close(p.closed) })
		return nil, errors.New("test: commit failed")
	}
	c1, c2 := net.Pipe()
	go func() {
		result, _ := wire.WriteFlowResult(wire.FlowResult{Status: wire.FlowStatusReady, Code: 0})
		_, _ = c2.Write(result[:])
		_ = c2.Close()
	}()
	p.once.Do(func() { close(p.committed) })
	return c1, nil
}

func (p *recordingPreparedStream) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

var _ quic.PreparedStream = (*recordingPreparedStream)(nil)

type prepareOKQuic struct {
	id       wire.SessionID
	prepared *recordingPreparedStream
}

func (q *prepareOKQuic) SetSessionID(id wire.SessionID) { q.id = id }
func (q *prepareOKQuic) AcquireSession(context.Context) (carrier.QuicSession, error) {
	if q.prepared == nil {
		q.prepared = &recordingPreparedStream{committed: make(chan struct{}), closed: make(chan struct{})}
	}
	return &fakeQuicSession{prep: q.prepared}, nil
}
func (q *prepareOKQuic) InvalidateSession(carrier.QuicSession) {}
func (q *prepareOKQuic) Close() error                          { return nil }

var _ quic.Backend = (*prepareOKQuic)(nil)

func TestOpenTCPClosesTCPOnQUICCommitFailure(t *testing.T) {
	spec := mustNowhereSpec(t)
	tcpDialer := newPipeTCPDialer()
	quic := &prepareOKQuic{prepared: &recordingPreparedStream{
		committed:  make(chan struct{}),
		closed:     make(chan struct{}),
		failCommit: true,
	}}
	tcpConfig, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address: "127.0.0.1:1", Spec: spec, Key: "k", Dialer: tcpDialer, TLSDialer: passthroughTLSDialer{},
	})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	bundle, err := NewCarrierBundle(BundleOptions{
		QUIC: quic, TCP: tcpConfig, Up: wire.CarrierTCP, Down: wire.CarrierUDP,
	})
	if err != nil {
		t.Fatalf("NewCarrierBundle: %v", err)
	}
	conn, err := bundle.OpenTCP(context.Background(), "example.com:443")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("expected commit failure")
	}
	select {
	case <-tcpDialer.closed:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("TCP half not closed after QUIC commit failure")
	}
}

func TestOpenTCPNoFLOWBeforeBothPrepared(t *testing.T) {
	spec := mustNowhereSpec(t)
	var mu sync.Mutex
	var sawRequest bool
	tcpDialer := &hookPipeDialer{onWrite: func(p []byte) {
		mu.Lock()
		defer mu.Unlock()
		if len(p) > 0 && p[0] == wire.FlowFrameMagic {
			sawRequest = true
		}
	}}
	quicReady := make(chan struct{})
	quic := &gatePrepareQuic{ready: quicReady}
	tcpConfig, err := tcptls.NewConfig(tcptls.TCPOptions{
		Address: "127.0.0.1:1", Spec: spec, Key: "k", Dialer: tcpDialer, TLSDialer: passthroughTLSDialer{},
	})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	bundle, err := NewCarrierBundle(BundleOptions{
		QUIC: quic, TCP: tcpConfig, Up: wire.CarrierTCP, Down: wire.CarrierUDP,
	})
	if err != nil {
		t.Fatalf("NewCarrierBundle: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		conn, err := bundle.OpenTCP(context.Background(), "example.com:443")
		if conn != nil {
			_ = conn.Close()
		}
		errCh <- err
	}()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if tcpDialer.prepared.Load() {
			break
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	leaked := sawRequest
	mu.Unlock()
	if leaked {
		t.Fatal("FLOW frame written before QUIC prepare completed")
	}
	close(quicReady)
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("OpenTCP: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("OpenTCP timed out")
	}
}

type hookPipeDialer struct {
	prepared atomic.Bool
	onWrite  func([]byte)
}

func (d *hookPipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		buf := make([]byte, 4096)
		for {
			n, err := c2.Read(buf)
			if n > 0 && d.onWrite != nil {
				d.onWrite(buf[:n])
			}
			if err != nil {
				return
			}
			d.prepared.Store(true)
		}
	}()
	return c1, nil
}

type gatePrepareQuic struct {
	ready <-chan struct{}
	id    wire.SessionID
}

func (q *gatePrepareQuic) SetSessionID(id wire.SessionID) { q.id = id }
func (q *gatePrepareQuic) AcquireSession(ctx context.Context) (carrier.QuicSession, error) {
	select {
	case <-q.ready:
		return &fakeQuicSession{prep: &recordingPreparedStream{committed: make(chan struct{}), closed: make(chan struct{})}}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (q *gatePrepareQuic) InvalidateSession(carrier.QuicSession) {}
func (q *gatePrepareQuic) Close() error                          { return nil }

var _ quic.Backend = (*gatePrepareQuic)(nil)

type capturedFlowSetup struct {
	header      wire.FlowHeader
	target      string
	finishWrite bool
	err         error
}

type recordingFlowTCPDialer struct {
	key        string
	spec       *wire.EffectiveSpec
	records    chan capturedFlowSetup
	resultGate <-chan struct{}
}

func (d *recordingFlowTCPDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if _, err := wire.ReadAuthFrame(server, d.key, d.spec); err != nil {
			d.records <- capturedFlowSetup{err: fmt.Errorf("read auth: %w", err)}
			return
		}
		record := decodeCapturedFlowSetup(server, d.spec)
		d.records <- record
		if record.err != nil {
			return
		}
		if record.header.Role == wire.FlowRoleAttach || record.header.Role == wire.FlowRoleDuplex {
			if d.resultGate != nil {
				<-d.resultGate
			}
			result, err := wire.WriteFlowResult(wire.FlowResult{Status: wire.FlowStatusReady})
			if err != nil {
				return
			}
			if _, err := server.Write(result[:]); err != nil {
				return
			}
		}
		_, _ = io.Copy(io.Discard, server)
	}()
	return client, nil
}

type recordingFlowPreparedStream struct {
	spec       *wire.EffectiveSpec
	records    chan capturedFlowSetup
	resultGate <-chan struct{}
}

func (p *recordingFlowPreparedStream) Commit(_ context.Context, setup []byte, finishWrite bool) (net.Conn, error) {
	reader := bytes.NewReader(setup)
	record := decodeCapturedFlowSetup(reader, p.spec)
	if record.err == nil && reader.Len() != 0 {
		record.err = fmt.Errorf("unexpected trailing setup bytes: %d", reader.Len())
	}
	record.finishWrite = finishWrite
	p.records <- record
	if record.err != nil {
		return nil, record.err
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if record.header.Role == wire.FlowRoleAttach || record.header.Role == wire.FlowRoleDuplex {
			if p.resultGate != nil {
				<-p.resultGate
			}
			result, err := wire.WriteFlowResult(wire.FlowResult{Status: wire.FlowStatusReady})
			if err != nil {
				return
			}
			if _, err := server.Write(result[:]); err != nil {
				return
			}
		}
		_, _ = io.Copy(io.Discard, server)
	}()
	return client, nil
}

func (p *recordingFlowPreparedStream) Close() error { return nil }

type recordingFlowQUIC struct {
	id   wire.SessionID
	prep *recordingFlowPreparedStream
}

func (q *recordingFlowQUIC) SetSessionID(id wire.SessionID) { q.id = id }
func (q *recordingFlowQUIC) AcquireSession(context.Context) (carrier.QuicSession, error) {
	return &fakeQuicSession{prep: q.prep}, nil
}
func (q *recordingFlowQUIC) InvalidateSession(carrier.QuicSession) {}
func (q *recordingFlowQUIC) Close() error                          { return nil }

func decodeCapturedFlowSetup(r io.Reader, spec *wire.EffectiveSpec) capturedFlowSetup {
	header, err := wire.ReadFlowHeader(r)
	if err != nil {
		return capturedFlowSetup{err: fmt.Errorf("read flow header: %w", err)}
	}
	record := capturedFlowSetup{header: header}
	if header.Role != wire.FlowRoleAttach {
		record.target, record.err = wire.DecodeTCPRequest(r, spec)
		if record.err != nil {
			record.err = fmt.Errorf("read target: %w", record.err)
		}
	}
	return record
}

func receiveCapturedFlowSetup(t *testing.T, records <-chan capturedFlowSetup) capturedFlowSetup {
	t.Helper()
	select {
	case record := <-records:
		if record.err != nil {
			t.Fatalf("capture flow setup: %v", record.err)
		}
		return record
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for flow setup")
		return capturedFlowSetup{}
	}
}

func closeFlowResultGate(gate chan struct{}) {
	select {
	case <-gate:
	default:
		close(gate)
	}
}

type openTCPResult struct {
	conn net.Conn
	err  error
}

func awaitOpenTCP(t *testing.T, result <-chan openTCPResult) net.Conn {
	t.Helper()
	select {
	case opened := <-result:
		if opened.err != nil {
			t.Fatalf("OpenTCP: %v", opened.err)
		}
		if opened.conn == nil {
			t.Fatal("OpenTCP returned nil connection")
		}
		return opened.conn
	case <-time.After(time.Second):
		t.Fatal("OpenTCP timed out")
		return nil
	}
}

func assertOpenTCPWaitsForDownlink(t *testing.T, result <-chan openTCPResult) {
	t.Helper()
	select {
	case opened := <-result:
		if opened.conn != nil {
			_ = opened.conn.Close()
		}
		t.Fatalf("OpenTCP returned before downlink FLOW_RESULT: %v", opened.err)
	case <-time.After(25 * time.Millisecond):
	}
}

func TestAsymmetricTCPSetupMatchesOracle(t *testing.T) {
	const target = "example.com:443"
	for _, tc := range []struct {
		name           string
		up, down       wire.Carrier
		wantTCPRole    wire.FlowRole
		wantQUICRole   wire.FlowRole
		wantTCPtarget  string
		wantQUICtarget string
		wantQUICFinish bool
	}{
		{
			name: "tcp-quic", up: wire.CarrierTCP, down: wire.CarrierUDP,
			wantTCPRole: wire.FlowRoleOpen, wantQUICRole: wire.FlowRoleAttach,
			wantTCPtarget: target, wantQUICFinish: true,
		},
		{
			name: "quic-tcp", up: wire.CarrierUDP, down: wire.CarrierTCP,
			wantTCPRole: wire.FlowRoleAttach, wantQUICRole: wire.FlowRoleOpen,
			wantQUICtarget: target, wantQUICFinish: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := mustNowhereSpec(t)
			resultGate := make(chan struct{})
			t.Cleanup(func() { closeFlowResultGate(resultGate) })
			tcpRecords := make(chan capturedFlowSetup, 1)
			quicRecords := make(chan capturedFlowSetup, 1)
			tcpDialer := &recordingFlowTCPDialer{
				key: "k", spec: spec, records: tcpRecords, resultGate: resultGate,
			}
			quicBackend := &recordingFlowQUIC{prep: &recordingFlowPreparedStream{
				spec: spec, records: quicRecords, resultGate: resultGate,
			}}
			tcpConfig, err := tcptls.NewConfig(tcptls.TCPOptions{
				Address: "127.0.0.1:1", Spec: spec, Key: "k", Dialer: tcpDialer, TLSDialer: passthroughTLSDialer{},
			})
			if err != nil {
				t.Fatalf("NewConfig: %v", err)
			}
			bundle, err := NewCarrierBundle(BundleOptions{
				QUIC: quicBackend, TCP: tcpConfig, Up: tc.up, Down: tc.down,
			})
			if err != nil {
				t.Fatalf("NewCarrierBundle: %v", err)
			}
			t.Cleanup(bundle.Close)

			result := make(chan openTCPResult, 1)
			go func() {
				conn, err := bundle.OpenTCP(context.Background(), target)
				result <- openTCPResult{conn: conn, err: err}
			}()

			tcpRecord := receiveCapturedFlowSetup(t, tcpRecords)
			quicRecord := receiveCapturedFlowSetup(t, quicRecords)
			assertOpenTCPWaitsForDownlink(t, result)
			closeFlowResultGate(resultGate)
			conn := awaitOpenTCP(t, result)
			defer conn.Close()

			if tcpRecord.header.Role != tc.wantTCPRole || tcpRecord.target != tc.wantTCPtarget {
				t.Fatalf("TCP setup = role %d target %q, want role %d target %q", tcpRecord.header.Role, tcpRecord.target, tc.wantTCPRole, tc.wantTCPtarget)
			}
			if quicRecord.header.Role != tc.wantQUICRole || quicRecord.target != tc.wantQUICtarget {
				t.Fatalf("QUIC setup = role %d target %q, want role %d target %q", quicRecord.header.Role, quicRecord.target, tc.wantQUICRole, tc.wantQUICtarget)
			}
			if tcpRecord.header.FlowID == 0 || tcpRecord.header.FlowID != quicRecord.header.FlowID {
				t.Fatalf("flow ids = TCP %d QUIC %d, want same nonzero id", tcpRecord.header.FlowID, quicRecord.header.FlowID)
			}
			for carrierName, header := range map[string]wire.FlowHeader{"TCP": tcpRecord.header, "QUIC": quicRecord.header} {
				if header.Kind != wire.FlowKindTCP || header.Uplink != tc.up || header.Downlink != tc.down {
					t.Fatalf("%s metadata = kind %d up %d down %d, want TCP/%d/%d", carrierName, header.Kind, header.Uplink, header.Downlink, tc.up, tc.down)
				}
			}
			if quicRecord.finishWrite != tc.wantQUICFinish {
				t.Fatalf("QUIC finishWrite = %v, want %v for role %d", quicRecord.finishWrite, tc.wantQUICFinish, tc.wantQUICRole)
			}
		})
	}
}

func TestSymmetricTCPSetupMatchesOracle(t *testing.T) {
	const target = "example.com:443"
	for _, carrierKind := range []wire.Carrier{wire.CarrierTCP, wire.CarrierUDP} {
		name := carrierTransportName(carrierKind)
		t.Run(name, func(t *testing.T) {
			spec := mustNowhereSpec(t)
			resultGate := make(chan struct{})
			t.Cleanup(func() { closeFlowResultGate(resultGate) })
			tcpRecords := make(chan capturedFlowSetup, 1)
			quicRecords := make(chan capturedFlowSetup, 1)
			tcpDialer := &recordingFlowTCPDialer{
				key: "k", spec: spec, records: tcpRecords, resultGate: resultGate,
			}
			tcpConfig, err := tcptls.NewConfig(tcptls.TCPOptions{
				Address: "127.0.0.1:1", Spec: spec, Key: "k", Dialer: tcpDialer, TLSDialer: passthroughTLSDialer{},
			})
			if err != nil {
				t.Fatalf("NewConfig: %v", err)
			}
			var quicBackend carrier.QuicBackend
			if carrierKind == wire.CarrierUDP {
				quicBackend = &recordingFlowQUIC{prep: &recordingFlowPreparedStream{
					spec: spec, records: quicRecords, resultGate: resultGate,
				}}
			}
			bundle, err := NewCarrierBundle(BundleOptions{
				QUIC: quicBackend, TCP: tcpConfig, Up: carrierKind, Down: carrierKind,
			})
			if err != nil {
				t.Fatalf("NewCarrierBundle: %v", err)
			}
			t.Cleanup(bundle.Close)

			result := make(chan openTCPResult, 1)
			go func() {
				conn, err := bundle.OpenTCP(context.Background(), target)
				result <- openTCPResult{conn: conn, err: err}
			}()

			var record capturedFlowSetup
			if carrierKind == wire.CarrierTCP {
				record = receiveCapturedFlowSetup(t, tcpRecords)
			} else {
				record = receiveCapturedFlowSetup(t, quicRecords)
			}
			assertOpenTCPWaitsForDownlink(t, result)
			closeFlowResultGate(resultGate)
			conn := awaitOpenTCP(t, result)
			defer conn.Close()

			if record.header.Role != wire.FlowRoleDuplex || record.header.FlowID == 0 {
				t.Fatalf("duplex header = role %d flow_id %d", record.header.Role, record.header.FlowID)
			}
			if record.header.Kind != wire.FlowKindTCP || record.header.Uplink != carrierKind || record.header.Downlink != carrierKind {
				t.Fatalf("duplex metadata = kind %d up %d down %d, want TCP/%d/%d", record.header.Kind, record.header.Uplink, record.header.Downlink, carrierKind, carrierKind)
			}
			if record.target != target {
				t.Fatalf("duplex target = %q, want %q", record.target, target)
			}
			if carrierKind == wire.CarrierUDP && record.finishWrite {
				t.Fatal("QUIC duplex setup finished the uplink write side")
			}
		})
	}
}
