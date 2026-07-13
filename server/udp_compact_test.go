package server

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

type compactTestQuicConn struct {
	fakeQuicConn

	mu           sync.Mutex
	sent         chan []byte
	sendErr      error
	failCount    int
	blockStarted chan struct{}
	blockRelease <-chan struct{}
	blockType    uint8
	blockOnce    sync.Once
	closeRelease func()
	onSend       func([]byte)
	onSendCalled bool
}

func newCompactTestQuicConn() *compactTestQuicConn {
	return &compactTestQuicConn{sent: make(chan []byte, 64)}
}

func (c *compactTestQuicConn) SendDatagram(data []byte) error {
	c.mu.Lock()
	if c.sendErr != nil && c.failCount != 0 {
		if c.failCount > 0 {
			c.failCount--
		}
		err := c.sendErr
		c.mu.Unlock()
		return err
	}
	var onSend func([]byte)
	if c.onSend != nil && !c.onSendCalled {
		c.onSendCalled = true
		onSend = c.onSend
	}
	blockType := c.blockType
	c.mu.Unlock()
	if onSend != nil {
		onSend(data)
	}
	shouldBlock := c.blockStarted != nil && c.blockRelease != nil
	if shouldBlock && blockType != 0 {
		frame, err := wire.DecodeUDPCompact(data)
		shouldBlock = err == nil && frame.Type == blockType
	}
	if shouldBlock {
		block := false
		c.blockOnce.Do(func() {
			block = true
			close(c.blockStarted)
		})
		if block {
			<-c.blockRelease
		}
	}
	c.sent <- append([]byte(nil), data...)
	return nil
}

func (c *compactTestQuicConn) CloseWithError(code uint64, message string) error {
	err := c.fakeQuicConn.CloseWithError(code, message)
	if c.closeRelease != nil {
		c.closeRelease()
	}
	return err
}

func newCompactTestSession(t *testing.T, limits Limits, conn *compactTestQuicConn, routes chan<- packetRoute) *portalSession {
	t.Helper()
	config, err := NewConfig(ConfigOptions{Password: "secret", Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{
		Config: config,
		Upstream: upstreamFuncs{packet: func(_ context.Context, pc net.PacketConn, _ net.Addr, target string) error {
			if routes != nil {
				routes <- packetRoute{conn: pc, target: target}
			}
			return nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if conn == nil {
		conn = newCompactTestQuicConn()
	}
	session := newPortalSession(wire.SessionID{0x44}, conn, handler, &net.UDPAddr{IP: net.ParseIP("192.0.2.44"), Port: 4444})
	t.Cleanup(func() {
		session.Close()
		_ = handler.Close()
	})
	return session
}

func compactOpenFrame(t *testing.T, flowID uint64, downlink wire.Carrier, target string, payload []byte) wire.CompactUDPFrame {
	t.Helper()
	encoded, err := wire.EncodeUDPOpenData(flowID, downlink, target, payload)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := wire.DecodeUDPCompact(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func compactControlFrame(t *testing.T, frameType uint8, flowID uint64, payload []byte) wire.CompactUDPFrame {
	t.Helper()
	encoded, err := wire.EncodeUDPCompact(frameType, flowID, payload)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := wire.DecodeUDPCompact(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func awaitCompactFrame(t *testing.T, sent <-chan []byte, frameType uint8, flowID uint64) wire.CompactUDPFrame {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case data := <-sent:
			frame, err := wire.DecodeUDPCompact(data)
			if err != nil {
				t.Fatalf("DecodeUDPCompact: %v", err)
			}
			if frame.Type == frameType && frame.FlowID == flowID {
				return frame
			}
		case <-timer.C:
			t.Fatalf("Compact frame type=%d flow=%d was not sent", frameType, flowID)
		}
	}
}

func assertNoCompactFrame(t *testing.T, sent <-chan []byte) {
	t.Helper()
	select {
	case data := <-sent:
		frame, err := wire.DecodeUDPCompact(data)
		if err != nil {
			t.Fatalf("unexpected datagram %x: %v", data, err)
		}
		t.Fatalf("unexpected Compact frame type=%d flow=%d", frame.Type, frame.FlowID)
	case <-time.After(20 * time.Millisecond):
	}
}

func waitForCompactState(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		runtime.Gosched()
	}
	t.Fatal(message)
}

func activateCompactAsymmetric(t *testing.T, session *portalSession, routes <-chan packetRoute, flowID uint64, target string, payload []byte) (packetRoute, *udpPairTestDownlink) {
	t.Helper()
	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierTCP, target, payload))
	waitForCompactState(t, func() bool {
		records, pending, _ := udpPairManagerCounts(session.Handler.pairing, session.ID)
		return records == 1 && pending == 1
	}, "asymmetric Compact OPEN did not enter waiting pair state")
	_, attach := udpPairHeaders(flowID)
	downlink := newUDPPairTestDownlink()
	if err := session.Handler.submitAndRouteUDP(context.Background(), session.Source, session.ID, attach, target, udpHalf{Role: wire.FlowRoleAttach, Downlink: downlink}); err != nil {
		t.Fatal(err)
	}
	return awaitPacketRoute(t, routes), downlink
}

type compactAckBarrierDownlink struct {
	ackStarted  chan struct{}
	releaseAck  chan struct{}
	closed      chan struct{}
	ackOnce     sync.Once
	releaseOnce sync.Once
	closeOnce   sync.Once
}

func newCompactAckBarrierDownlink() *compactAckBarrierDownlink {
	return &compactAckBarrierDownlink{
		ackStarted: make(chan struct{}),
		releaseAck: make(chan struct{}),
		closed:     make(chan struct{}),
	}
}

func (d *compactAckBarrierDownlink) WritePacket([]byte) error { return nil }
func (d *compactAckBarrierDownlink) WriteAck(uint64) error {
	d.ackOnce.Do(func() { close(d.ackStarted) })
	<-d.releaseAck
	return nil
}
func (d *compactAckBarrierDownlink) WriteClose(uint64) error { return nil }
func (d *compactAckBarrierDownlink) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}
func (d *compactAckBarrierDownlink) release() {
	d.releaseOnce.Do(func() { close(d.releaseAck) })
}

func TestCompactRevokedOldAckCannotCrossFlowIDGeneration(t *testing.T) {
	routes := make(chan packetRoute, 1)
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, conn, routes)
	const flowID = uint64(117)
	const target = "revoked-ack.example:53"

	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierTCP, target, []byte("old-open")))
	waitForCompactState(t, func() bool {
		records, pending, _ := udpPairManagerCounts(session.Handler.pairing, session.ID)
		return records == 1 && pending == 1
	}, "old asymmetric Compact OPEN did not enter waiting state")
	oldEntry := session.getCompactEntry(flowID)
	if oldEntry == nil || oldEntry.lease == nil {
		t.Fatalf("old Compact entry = %+v, want ACK state", oldEntry)
	}
	_, attach := udpPairHeaders(flowID)
	downlink := newCompactAckBarrierDownlink()
	defer downlink.release()
	if err := session.Handler.submitAndRouteUDP(context.Background(), session.Source, session.ID, attach, target, udpHalf{Role: wire.FlowRoleAttach, Downlink: downlink}); err != nil {
		t.Fatal(err)
	}
	route := awaitPacketRoute(t, routes)
	readDone := make(chan error, 1)
	go func() {
		_, _, err := route.conn.ReadFrom(make([]byte, 64))
		readDone <- err
	}()
	select {
	case <-downlink.ackStarted:
	case <-time.After(time.Second):
		t.Fatal("old paired ACK path did not reach the barrier")
	}

	session.finishCompactEntry(oldEntry, net.ErrClosed, false)
	newEntry := stageCompactAsymmetricForTest(t, session, flowID, target, []byte("new-open"))
	if newEntry.generation == oldEntry.generation {
		t.Fatalf("reused generation = old generation %d", oldEntry.generation)
	}
	downlink.release()
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("revoked old ACK path did not return")
	}

	if oldEntry.lease.Acked() {
		t.Fatal("revoked old ACK marked generation 1 acknowledged")
	}
	select {
	case data := <-conn.sent:
		frame, err := wire.DecodeUDPCompact(data)
		if err != nil {
			t.Fatalf("DecodeUDPCompact: %v", err)
		}
		t.Fatalf("revoked old generation sent Compact frame type=%d flow=%d", frame.Type, frame.FlowID)
	default:
	}
	if current := session.getCompactEntry(flowID); current != newEntry {
		t.Fatalf("revoked old ACK affected reused entry: %+v", current)
	}
	if !newEntry.deliver([]byte("new-data")) {
		t.Fatal("reused entry rejected new generation data")
	}
	newUplink, ok := newEntry.pair.record.open.Uplink.(*quicUDPUplink)
	if !ok {
		t.Fatalf("reused uplink type = %T", newEntry.pair.record.open.Uplink)
	}
	for _, want := range []string{"new-open", "new-data"} {
		payload, err := newUplink.ReadPacket()
		if err != nil {
			t.Fatal(err)
		}
		if got := string(payload); got != want {
			t.Fatalf("reused generation payload = %q, want %q", got, want)
		}
	}
}

func newManualCompactTestEntry(session *portalSession, flowID uint64, target string, send func([]byte) error) (*compactUDPFlow, *compactUDPEntry) {
	if send == nil {
		send = session.SendDatagram
	}
	flow := newCompactUDPFlow(session, flowID, target, wire.CarrierUDP)
	entry := &compactUDPEntry{
		flowID:    flowID,
		target:    target,
		downlink:  wire.CarrierUDP,
		lease:     &compactGenerationLease{flowID: flowID, send: send},
		symmetric: flow,
	}
	return flow, entry
}

func compactRegistrySnapshot(session *portalSession, flowID uint64) (*compactUDPEntry, int) {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.udp.compact[flowID], session.udp.activeFlows
}

func compactFrameCounts(sent <-chan []byte) map[uint8]int {
	counts := make(map[uint8]int)
	for {
		select {
		case data := <-sent:
			frame, err := wire.DecodeUDPCompact(data)
			if err == nil {
				counts[frame.Type]++
			}
		default:
			return counts
		}
	}
}

func TestCompactRetireCleanupAndCloseBarrierBlocksFlowIDReuse(t *testing.T) {
	releaseClose := make(chan struct{})
	var releaseOnce sync.Once
	forceRelease := func() { releaseOnce.Do(func() { close(releaseClose) }) }
	defer forceRelease()
	conn := newCompactTestQuicConn()
	conn.blockStarted = make(chan struct{})
	conn.blockRelease = releaseClose
	conn.blockType = wire.UDPTypeCompactClose
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, conn, nil)
	const flowID = uint64(121)

	oldFlow, oldEntry := newManualCompactTestEntry(session, flowID, "cleanup-close-old.example:53", nil)
	defer oldFlow.shutdown(net.ErrClosed)
	if !session.reserveCompactEntry(oldEntry) {
		t.Fatal("old Compact entry reservation failed")
	}
	stopCompactIdle(oldFlow)
	finishDone := make(chan struct{})
	go func() {
		session.finishCompactEntry(oldEntry, net.ErrClosed, true)
		close(finishDone)
	}()
	select {
	case <-conn.blockStarted:
	case <-time.After(time.Second):
		t.Fatal("terminal Compact CLOSE did not reach the barrier")
	}

	rawEntry, activeFlows := compactRegistrySnapshot(session, flowID)
	newFlow, newEntry := newManualCompactTestEntry(session, flowID, "cleanup-close-new.example:53", nil)
	defer newFlow.shutdown(net.ErrClosed)
	reservedEarly := session.reserveCompactEntry(newEntry)
	forceRelease()
	select {
	case <-finishDone:
	case <-time.After(time.Second):
		t.Fatal("retire did not finish after releasing terminal CLOSE")
	}
	if rawEntry != oldEntry || activeFlows != 1 {
		t.Fatalf("retiring cleanup tombstone entry=%p active=%d, want old entry/1", rawEntry, activeFlows)
	}
	if reservedEarly {
		t.Fatal("flow ID reuse succeeded before cleanup and terminal CLOSE completed")
	}
	if rawEntry, activeFlows = compactRegistrySnapshot(session, flowID); rawEntry != nil || activeFlows != 0 {
		t.Fatalf("completed retire entry=%p active=%d, want nil/0", rawEntry, activeFlows)
	}
	if !session.reserveCompactEntry(newEntry) {
		t.Fatal("generation 2 reservation failed after cleanup and terminal CLOSE")
	}
	if newEntry.generation == oldEntry.generation {
		t.Fatalf("generation 2 reused old generation %d", oldEntry.generation)
	}
}

func TestPortalSessionCloseInterruptsBlockedCompactAckSend(t *testing.T) {
	releaseSend := make(chan struct{})
	var releaseOnce sync.Once
	forceRelease := func() { releaseOnce.Do(func() { close(releaseSend) }) }
	defer forceRelease()
	conn := newCompactTestQuicConn()
	conn.blockStarted = make(chan struct{})
	conn.blockRelease = releaseSend
	conn.closeRelease = forceRelease
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, conn, nil)
	const flowID = uint64(118)

	flow := newCompactUDPFlow(session, flowID, "close-blocked-ack.example:53", wire.CarrierUDP)
	entry := &compactUDPEntry{
		flowID:    flowID,
		target:    flow.target,
		downlink:  flow.downlink,
		lease:     &compactGenerationLease{flowID: flowID, send: session.SendDatagram},
		symmetric: flow,
	}
	if !session.reserveCompactEntry(entry) {
		t.Fatal("Compact entry reservation failed")
	}
	stopCompactIdle(flow)
	ackDone := make(chan error, 1)
	go func() { ackDone <- entry.lease.SendOpenAck() }()
	select {
	case <-conn.blockStarted:
	case <-time.After(time.Second):
		t.Fatal("OPEN_ACK send did not enter the blocking SendDatagram")
	}

	closeDone := make(chan struct{})
	go func() {
		session.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(250 * time.Millisecond):
		forceRelease()
		<-closeDone
		<-ackDone
		t.Fatal("portalSession.Close waited for blocked Compact ACK before CloseWithError")
	}
	select {
	case err := <-ackDone:
		if !errors.Is(err, errCompactAckRevoked) {
			t.Fatalf("blocked ACK completion error = %v, want errCompactAckRevoked", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CloseWithError did not release blocked Compact ACK send")
	}
	if got := conn.closeWithErrorCalls.Load(); got != 1 {
		t.Fatalf("CloseWithError calls = %d, want 1", got)
	}
	if entry.lease.Acked() {
		t.Fatal("ACK completed after session close was marked acknowledged")
	}
}

func TestCompactRevokingEntryBlocksReuseUntilAckSendCompletes(t *testing.T) {
	releaseAck := make(chan struct{})
	releaseClose := make(chan struct{})
	var releaseAckOnce sync.Once
	var releaseCloseOnce sync.Once
	forceReleaseAck := func() { releaseAckOnce.Do(func() { close(releaseAck) }) }
	forceReleaseClose := func() { releaseCloseOnce.Do(func() { close(releaseClose) }) }
	defer forceReleaseAck()
	defer forceReleaseClose()

	conn := newCompactTestQuicConn()
	connCloseStarted := make(chan struct{})
	conn.blockStarted = connCloseStarted
	conn.blockRelease = releaseClose
	conn.blockType = wire.UDPTypeCompactClose
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, conn, nil)
	const flowID = uint64(119)

	ackStarted := make(chan struct{})
	leaseCloseStarted := make(chan struct{})
	var ackStartedOnce sync.Once
	var leaseCloseStartedOnce sync.Once
	send := func(data []byte) error {
		frame, err := wire.DecodeUDPCompact(data)
		if err != nil {
			return err
		}
		switch frame.Type {
		case wire.UDPTypeOpenAck:
			ackStartedOnce.Do(func() { close(ackStarted) })
			<-releaseAck
		case wire.UDPTypeCompactClose:
			leaseCloseStartedOnce.Do(func() { close(leaseCloseStarted) })
			<-releaseClose
		}
		return session.SendDatagram(data)
	}
	oldFlow, oldEntry := newManualCompactTestEntry(session, flowID, "revoking-old.example:53", send)
	defer oldFlow.shutdown(net.ErrClosed)
	if !session.reserveCompactEntry(oldEntry) {
		t.Fatal("old Compact entry reservation failed")
	}
	stopCompactIdle(oldFlow)

	ackDone := make(chan error, 1)
	go func() { ackDone <- oldEntry.lease.SendOpenAck() }()
	select {
	case <-ackStarted:
	case <-time.After(time.Second):
		t.Fatal("old OPEN_ACK send did not enter SendDatagram")
	}

	finishDone := make(chan struct{})
	go func() {
		session.finishCompactEntry(oldEntry, net.ErrClosed, true)
		close(finishDone)
	}()
	select {
	case <-leaseCloseStarted:
	case <-connCloseStarted:
	case <-time.After(time.Second):
		t.Fatal("terminal Compact CLOSE did not reach a generation barrier")
	}

	forceReleaseAck()
	select {
	case err := <-ackDone:
		if !errors.Is(err, errCompactAckRevoked) {
			t.Errorf("revoked in-flight ACK error = %v, want errCompactAckRevoked", err)
		}
	case <-time.After(time.Second):
		t.Fatal("released old ACK send did not return")
	}
	if oldEntry.lease.Acked() {
		t.Error("revoked in-flight ACK marked the old entry acknowledged")
	}

	rawEntry, activeFlows := compactRegistrySnapshot(session, flowID)
	newFlow, newEntry := newManualCompactTestEntry(session, flowID, "revoking-new.example:53", nil)
	defer newFlow.shutdown(net.ErrClosed)
	reservedEarly := session.reserveCompactEntry(newEntry)
	if rawEntry != oldEntry || activeFlows != 1 {
		t.Errorf("ACK-drained tombstone entry=%p active=%d, want old entry/1 until terminal CLOSE completes", rawEntry, activeFlows)
	}
	if reservedEarly {
		t.Error("flow ID reuse succeeded after ACK drain but before terminal CLOSE completed")
	}

	forceReleaseClose()
	select {
	case <-finishDone:
	case <-time.After(time.Second):
		t.Fatal("retire did not finish after terminal CLOSE release")
	}
	if !reservedEarly {
		if rawEntry, activeFlows = compactRegistrySnapshot(session, flowID); rawEntry != nil || activeFlows != 0 {
			t.Fatalf("completed generation entry=%p active=%d, want nil/0", rawEntry, activeFlows)
		}
		if !session.reserveCompactEntry(newEntry) {
			t.Fatal("generation 2 reservation failed after ACK, cleanup, and terminal CLOSE drained")
		}
	}
	if newEntry.generation == oldEntry.generation {
		t.Fatalf("generation 2 reused old generation %d", oldEntry.generation)
	}
}

func TestCompactBlockedOldDataSendBlocksFlowIDReuse(t *testing.T) {
	releaseData := make(chan struct{})
	var releaseOnce sync.Once
	forceRelease := func() { releaseOnce.Do(func() { close(releaseData) }) }
	defer forceRelease()
	conn := newCompactTestQuicConn()
	conn.blockStarted = make(chan struct{})
	conn.blockRelease = releaseData
	conn.blockType = wire.UDPTypeData
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, conn, nil)
	const flowID = uint64(122)

	oldFlow, oldEntry := newManualCompactTestEntry(session, flowID, "blocked-data-old.example:53", nil)
	defer oldFlow.shutdown(net.ErrClosed)
	if !session.reserveCompactEntry(oldEntry) {
		t.Fatal("old Compact entry reservation failed")
	}
	stopCompactIdle(oldFlow)
	type writeResult struct {
		n   int
		err error
	}
	writeDone := make(chan writeResult, 1)
	go func() {
		n, err := oldFlow.WriteTo([]byte("old-data"), nil)
		writeDone <- writeResult{n: n, err: err}
	}()
	select {
	case <-conn.blockStarted:
	case <-time.After(time.Second):
		t.Fatal("old generation DATA did not reach SendDatagram barrier")
	}

	finishDone := make(chan struct{})
	go func() {
		session.finishCompactEntry(oldEntry, net.ErrClosed, true)
		close(finishDone)
	}()
	select {
	case <-finishDone:
	case <-time.After(time.Second):
		t.Fatal("retire waited for an admitted DATA send")
	}
	rawEntry, activeFlows := compactRegistrySnapshot(session, flowID)
	newFlow, newEntry := newManualCompactTestEntry(session, flowID, "blocked-data-new.example:53", nil)
	defer newFlow.shutdown(net.ErrClosed)
	reservedEarly := session.reserveCompactEntry(newEntry)

	forceRelease()
	var result writeResult
	select {
	case result = <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("blocked old DATA send did not return after release")
	}
	if rawEntry != oldEntry || activeFlows != 1 {
		t.Errorf("DATA-in-flight tombstone entry=%p active=%d, want old entry/1", rawEntry, activeFlows)
	}
	if reservedEarly {
		t.Error("flow ID reuse succeeded while old generation DATA remained in flight")
	}
	if result.n != 0 || (!errors.Is(result.err, errCompactAckRevoked) && !errors.Is(result.err, net.ErrClosed)) {
		t.Errorf("retired old DATA result = (%d, %v), want 0 and revoked/closed", result.n, result.err)
	}

	if !reservedEarly {
		waitForCompactState(t, func() bool {
			entry, active := compactRegistrySnapshot(session, flowID)
			return entry == nil && active == 0
		}, "old DATA drain did not finalize the Compact generation")
		if !session.reserveCompactEntry(newEntry) {
			t.Fatal("generation 2 reservation failed after old DATA drain")
		}
	}
	if newEntry.generation == oldEntry.generation {
		t.Fatalf("generation 2 reused old generation %d", oldEntry.generation)
	}
	counts := compactFrameCounts(conn.sent)
	if counts[wire.UDPTypeData] != 1 || counts[wire.UDPTypeCompactClose] != 1 {
		t.Errorf("old generation frame counts DATA=%d CLOSE=%d, want 1/1", counts[wire.UDPTypeData], counts[wire.UDPTypeCompactClose])
	}
	session.finishCompactEntry(oldEntry, io.EOF, true)
	if extra := compactFrameCounts(conn.sent); extra[wire.UDPTypeCompactClose] != 0 {
		t.Errorf("late old callback emitted %d extra terminal CLOSE frames", extra[wire.UDPTypeCompactClose])
	}
	if current := session.getCompactEntry(flowID); current != newEntry {
		t.Errorf("late old callback affected generation 2: %+v", current)
	}
}

func TestCompactGenerationSendReentrantFinishDoesNotDeadlock(t *testing.T) {
	config, err := NewConfig(ConfigOptions{Password: "secret", Limits: Limits{QUICFlowsPerSession: 1}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}})
	if err != nil {
		t.Fatal(err)
	}
	conn := newCompactTestQuicConn()
	session := newPortalSession(wire.SessionID{0x45}, conn, handler, &net.UDPAddr{IP: net.ParseIP("192.0.2.45"), Port: 4545})
	completed := false
	defer func() {
		if completed {
			session.Close()
			_ = handler.Close()
		}
	}()
	const flowID = uint64(123)
	oldFlow, oldEntry := newManualCompactTestEntry(session, flowID, "reentrant-data.example:53", nil)
	if !session.reserveCompactEntry(oldEntry) {
		t.Fatal("reentrant Compact entry reservation failed")
	}
	stopCompactIdle(oldFlow)
	conn.onSend = func(data []byte) {
		frame, decodeErr := wire.DecodeUDPCompact(data)
		if decodeErr == nil && frame.Type == wire.UDPTypeData {
			session.finishCompactEntry(oldEntry, net.ErrClosed, false)
		}
	}

	type writeResult struct {
		n   int
		err error
	}
	writeDone := make(chan writeResult, 1)
	go func() {
		n, writeErr := oldFlow.WriteTo([]byte("reentrant"), nil)
		writeDone <- writeResult{n: n, err: writeErr}
	}()
	var result writeResult
	select {
	case result = <-writeDone:
		completed = true
	case <-time.After(250 * time.Millisecond):
		t.Fatal("synchronous reentrant Compact finish deadlocked generation send")
	}
	if result.n != 0 || (!errors.Is(result.err, errCompactAckRevoked) && !errors.Is(result.err, net.ErrClosed)) {
		t.Fatalf("reentrantly retired DATA result = (%d, %v), want 0 and revoked/closed", result.n, result.err)
	}
}

func TestCompactRevokingEntryDoesNotEmitUnknownClose(t *testing.T) {
	releaseClose := make(chan struct{})
	var releaseOnce sync.Once
	forceRelease := func() { releaseOnce.Do(func() { close(releaseClose) }) }
	defer forceRelease()
	conn := newCompactTestQuicConn()
	conn.blockStarted = make(chan struct{})
	conn.blockRelease = releaseClose
	conn.blockType = wire.UDPTypeCompactClose
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, conn, nil)
	const flowID = uint64(124)
	const target = "revoking-ingress.example:53"

	oldFlow, oldEntry := newManualCompactTestEntry(session, flowID, target, nil)
	defer oldFlow.shutdown(net.ErrClosed)
	if !session.reserveCompactEntry(oldEntry) {
		t.Fatal("old Compact entry reservation failed")
	}
	stopCompactIdle(oldFlow)
	finishDone := make(chan struct{})
	go func() {
		session.finishCompactEntry(oldEntry, net.ErrClosed, true)
		close(finishDone)
	}()
	select {
	case <-conn.blockStarted:
	case <-time.After(time.Second):
		t.Fatal("terminal Compact CLOSE did not reach the barrier")
	}

	session.handleCompactFrame(context.Background(), compactControlFrame(t, wire.UDPTypeData, flowID, []byte("late-data")))
	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierUDP, target, []byte("late-open")))
	rawEntry, activeFlows := compactRegistrySnapshot(session, flowID)
	beforeRelease := compactFrameCounts(conn.sent)
	forceRelease()
	select {
	case <-finishDone:
	case <-time.After(time.Second):
		t.Fatal("retire did not finish after terminal CLOSE release")
	}
	if rawEntry != oldEntry || activeFlows != 1 {
		t.Errorf("revoking ingress replaced tombstone entry=%p active=%d, want old entry/1", rawEntry, activeFlows)
	}
	for frameType, count := range beforeRelease {
		if count != 0 {
			t.Errorf("revoking ingress emitted frame type=%d count=%d before old terminal CLOSE completed", frameType, count)
		}
	}
}

func TestCompactAsymmetricQUICDownlinkUsesGenerationLease(t *testing.T) {
	releaseData := make(chan struct{})
	var releaseOnce sync.Once
	forceRelease := func() { releaseOnce.Do(func() { close(releaseData) }) }
	defer forceRelease()
	conn := newCompactTestQuicConn()
	conn.blockStarted = make(chan struct{})
	conn.blockRelease = releaseData
	conn.blockType = wire.UDPTypeData
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, conn, nil)
	const flowID = uint64(125)
	const target = "paired-quic-lease.example:53"

	ack := &compactGenerationLease{flowID: flowID, send: session.SendDatagram}
	uplink := newUDPPairTestUplink()
	header := wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		FlowID:   flowID,
		Kind:     wire.FlowKindUDP,
		Uplink:   wire.CarrierTCP,
		Downlink: wire.CarrierUDP,
	}
	half := udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink, compactLease: ack}
	handle, err := session.Handler.pairing.stageUDPWithSource(context.Background(), session.ID, header, target, half, session.Source, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	oldEntry := &compactUDPEntry{flowID: flowID, target: target, downlink: wire.CarrierUDP, lease: ack, pair: handle}
	if !session.reserveCompactEntry(oldEntry) {
		session.Handler.pairing.finishUDP(handle, errCompactFlowRejected)
		t.Fatal("paired QUIC Compact entry reservation failed")
	}
	if !session.Handler.pairing.setUDPFinish(handle, func(cause error) {
		session.finishCompactEntry(oldEntry, cause, true)
	}) {
		t.Fatal("paired QUIC finish callback installation failed")
	}
	attach := header
	attach.Role = wire.FlowRoleAttach
	if _, paired, submitErr := session.Handler.pairing.SubmitUDP(context.Background(), session.ID, attach, target, udpHalf{Role: wire.FlowRoleAttach, Downlink: newQUICUDPDownlink(session.SendDatagram)}); submitErr != nil || paired != nil {
		t.Fatalf("paired QUIC attach = (%v, %v), want staged nil pair", paired, submitErr)
	}
	paired, ok := session.Handler.pairing.admitUDP(handle)
	if !ok || paired == nil {
		t.Fatalf("paired QUIC admit = (%v, %v), want completed pair", paired, ok)
	}
	paired.IdleTimeout = time.Second
	pairedConn := newPairedUDPConn(paired)
	pairedConn.setFinish(func(cause error) { session.Handler.pairing.finishUDP(handle, cause) })
	if !session.Handler.pairing.bindUDP(handle, pairedConn) {
		t.Fatal("paired QUIC bind failed")
	}

	uplink.Deliver([]byte("request"))
	buffer := make([]byte, 64)
	if n, _, readErr := pairedConn.ReadFrom(buffer); readErr != nil || string(buffer[:n]) != "request" {
		t.Fatalf("paired QUIC ReadFrom = (%q, %v), want request/nil", buffer[:n], readErr)
	}
	type writeResult struct {
		n   int
		err error
	}
	writeDone := make(chan writeResult, 1)
	go func() {
		n, writeErr := pairedConn.WriteTo([]byte("response"), nil)
		writeDone <- writeResult{n: n, err: writeErr}
	}()
	select {
	case <-conn.blockStarted:
	case <-time.After(time.Second):
		t.Fatal("paired QUIC DATA did not reach SendDatagram barrier")
	}

	finishDone := make(chan struct{})
	go func() {
		session.finishCompactEntry(oldEntry, net.ErrClosed, true)
		close(finishDone)
	}()
	select {
	case <-finishDone:
	case <-time.After(time.Second):
		t.Fatal("active pair retire waited for admitted QUIC DATA")
	}
	rawEntry, activeFlows := compactRegistrySnapshot(session, flowID)
	newFlow, newEntry := newManualCompactTestEntry(session, flowID, "paired-quic-new.example:53", nil)
	defer newFlow.shutdown(net.ErrClosed)
	reservedEarly := session.reserveCompactEntry(newEntry)

	forceRelease()
	var result writeResult
	select {
	case result = <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("paired QUIC DATA did not return after release")
	}
	if rawEntry != oldEntry || activeFlows != 1 {
		t.Errorf("paired DATA-in-flight tombstone entry=%p active=%d, want old entry/1", rawEntry, activeFlows)
	}
	if reservedEarly {
		t.Error("paired QUIC flow ID reuse succeeded while old DATA remained in flight")
	}
	if result.n != 0 || (!errors.Is(result.err, errCompactAckRevoked) && !errors.Is(result.err, net.ErrClosed)) {
		t.Errorf("retired paired QUIC DATA result = (%d, %v), want 0 and revoked/closed", result.n, result.err)
	}
	if !reservedEarly {
		waitForCompactState(t, func() bool {
			entry, active := compactRegistrySnapshot(session, flowID)
			return entry == nil && active == 0
		}, "paired QUIC DATA drain did not finalize generation")
		if !session.reserveCompactEntry(newEntry) {
			t.Fatal("generation 2 reservation failed after paired QUIC drain")
		}
	}
	if newEntry.generation == oldEntry.generation {
		t.Fatalf("generation 2 reused old generation %d", oldEntry.generation)
	}
	counts := compactFrameCounts(conn.sent)
	if counts[wire.UDPTypeOpenAck] != 1 || counts[wire.UDPTypeData] != 1 || counts[wire.UDPTypeCompactClose] != 1 {
		t.Errorf("paired QUIC frame counts ACK=%d DATA=%d CLOSE=%d, want 1/1/1", counts[wire.UDPTypeOpenAck], counts[wire.UDPTypeData], counts[wire.UDPTypeCompactClose])
	}
	session.finishCompactEntry(oldEntry, io.EOF, true)
	if extra := compactFrameCounts(conn.sent); extra[wire.UDPTypeCompactClose] != 0 {
		t.Errorf("late paired callback emitted %d extra terminal CLOSE frames", extra[wire.UDPTypeCompactClose])
	}
	if current := session.getCompactEntry(flowID); current != newEntry {
		t.Errorf("late paired callback affected generation 2: %+v", current)
	}
}

func TestCompactWaitingCleanupBeforeRetireIsLatched(t *testing.T) {
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, conn, nil)
	const flowID = uint64(126)
	const target = "waiting-cleanup-before-retire.example:53"

	lease := &compactGenerationLease{flowID: flowID, send: session.SendDatagram}
	uplink := newUDPPairTestUplink()
	header := wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		FlowID:   flowID,
		Kind:     wire.FlowKindUDP,
		Uplink:   wire.CarrierUDP,
		Downlink: wire.CarrierTCP,
	}
	half := udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink, compactLease: lease}
	handle, err := session.Handler.pairing.stageUDPWithSource(context.Background(), session.ID, header, target, half, session.Source, "udp")
	if err != nil {
		t.Fatal(err)
	}
	oldEntry := &compactUDPEntry{flowID: flowID, target: target, downlink: wire.CarrierTCP, lease: lease, pair: handle}
	if !session.reserveCompactEntry(oldEntry) {
		session.Handler.pairing.finishUDP(handle, errCompactFlowRejected)
		t.Fatal("waiting Compact entry reservation failed")
	}

	cause := errors.New("finish waiting before callback install")
	session.Handler.pairing.finishUDP(handle, cause)
	select {
	case <-uplink.closed:
	case <-time.After(time.Second):
		t.Fatal("waiting Compact physical cleanup did not complete")
	}
	if session.Handler.pairing.setUDPFinish(handle, func(finishCause error) {
		session.finishCompactEntry(oldEntry, finishCause, true)
	}) {
		t.Fatal("setUDPFinish accepted a waiting record already physically closed")
	}

	session.finishCompactEntry(oldEntry, cause, true)
	rawEntry, activeFlows := compactRegistrySnapshot(session, flowID)
	counts := compactFrameCounts(conn.sent)
	newFlow, newEntry := newManualCompactTestEntry(session, flowID, "waiting-cleanup-reused.example:53", nil)
	defer newFlow.shutdown(net.ErrClosed)
	reserved := session.reserveCompactEntry(newEntry)

	session.Handler.pairing.finishUDP(handle, io.EOF)
	session.finishCompactEntry(oldEntry, io.EOF, true)
	extra := compactFrameCounts(conn.sent)
	if rawEntry != nil || activeFlows != 0 {
		t.Errorf("waiting pre-retire cleanup left entry=%p active=%d, want nil/0 after terminal CLOSE", rawEntry, activeFlows)
	}
	if !reserved {
		t.Error("waiting pre-retire cleanup left flow ID/quota unavailable for generation 2")
	} else if newEntry.generation == oldEntry.generation {
		t.Errorf("generation 2 reused old generation %d", oldEntry.generation)
	}
	if uplink.closeCount.Load() != 1 {
		t.Errorf("waiting uplink cleanup count = %d, want 1", uplink.closeCount.Load())
	}
	if counts[wire.UDPTypeCompactClose] != 1 {
		t.Errorf("waiting terminal CLOSE count = %d, want 1", counts[wire.UDPTypeCompactClose])
	}
	if extra[wire.UDPTypeCompactClose] != 0 {
		t.Errorf("late waiting cleanup emitted %d extra terminal CLOSE frames", extra[wire.UDPTypeCompactClose])
	}
	if reserved {
		if current := session.getCompactEntry(flowID); current != newEntry {
			t.Errorf("late waiting cleanup affected generation 2: %+v", current)
		}
	}
}

func TestCompactPairedBeforeBindCleanupBeforeRetireIsLatched(t *testing.T) {
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, conn, nil)
	const flowID = uint64(127)
	const target = "paired-cleanup-before-retire.example:53"

	lease := &compactGenerationLease{flowID: flowID, send: session.SendDatagram}
	uplink := newUDPPairTestUplink()
	header := wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		FlowID:   flowID,
		Kind:     wire.FlowKindUDP,
		Uplink:   wire.CarrierUDP,
		Downlink: wire.CarrierTCP,
	}
	half := udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink, compactLease: lease}
	handle, err := session.Handler.pairing.stageUDPWithSource(context.Background(), session.ID, header, target, half, session.Source, "udp")
	if err != nil {
		t.Fatal(err)
	}
	oldEntry := &compactUDPEntry{flowID: flowID, target: target, downlink: wire.CarrierTCP, lease: lease, pair: handle}
	if !session.reserveCompactEntry(oldEntry) {
		session.Handler.pairing.finishUDP(handle, errCompactFlowRejected)
		t.Fatal("paired-before-bind Compact entry reservation failed")
	}
	attach := header
	attach.Role = wire.FlowRoleAttach
	downlink := newUDPPairTestDownlink()
	if _, paired, submitErr := session.Handler.pairing.SubmitUDP(context.Background(), session.ID, attach, target, udpHalf{Role: wire.FlowRoleAttach, Downlink: downlink}); submitErr != nil || paired != nil {
		t.Fatalf("paired-before-bind attach = (%v, %v), want staged nil pair", paired, submitErr)
	}

	cause := errors.New("finish paired before callback install")
	session.Handler.pairing.finishUDP(handle, cause)
	select {
	case <-uplink.closed:
	case <-time.After(time.Second):
		t.Fatal("paired-before-bind uplink cleanup did not complete")
	}
	select {
	case <-downlink.closed:
	case <-time.After(time.Second):
		t.Fatal("paired-before-bind downlink cleanup did not complete")
	}
	if session.Handler.pairing.setUDPFinish(handle, func(finishCause error) {
		session.finishCompactEntry(oldEntry, finishCause, true)
	}) {
		t.Fatal("setUDPFinish accepted a paired record already physically closed")
	}

	session.finishCompactEntry(oldEntry, cause, true)
	rawEntry, activeFlows := compactRegistrySnapshot(session, flowID)
	counts := compactFrameCounts(conn.sent)
	newFlow, newEntry := newManualCompactTestEntry(session, flowID, "paired-cleanup-reused.example:53", nil)
	defer newFlow.shutdown(net.ErrClosed)
	reserved := session.reserveCompactEntry(newEntry)

	session.Handler.pairing.finishUDP(handle, io.EOF)
	session.finishCompactEntry(oldEntry, io.EOF, true)
	extra := compactFrameCounts(conn.sent)
	if rawEntry != nil || activeFlows != 0 {
		t.Errorf("paired-before-bind cleanup left entry=%p active=%d, want nil/0 after terminal CLOSE", rawEntry, activeFlows)
	}
	if !reserved {
		t.Error("paired-before-bind cleanup left flow ID/quota unavailable for generation 2")
	} else if newEntry.generation == oldEntry.generation {
		t.Errorf("generation 2 reused old generation %d", oldEntry.generation)
	}
	if uplink.closeCount.Load() != 1 || downlink.closeCount.Load() != 1 {
		t.Errorf("paired-before-bind cleanup counts uplink=%d downlink=%d, want 1/1", uplink.closeCount.Load(), downlink.closeCount.Load())
	}
	if counts[wire.UDPTypeCompactClose] != 1 {
		t.Errorf("paired-before-bind terminal CLOSE count = %d, want 1", counts[wire.UDPTypeCompactClose])
	}
	if extra[wire.UDPTypeCompactClose] != 0 {
		t.Errorf("late paired-before-bind cleanup emitted %d extra terminal CLOSE frames", extra[wire.UDPTypeCompactClose])
	}
	if reserved {
		if current := session.getCompactEntry(flowID); current != newEntry {
			t.Errorf("late paired-before-bind cleanup affected generation 2: %+v", current)
		}
	}
}

func TestCompactAckSendReentrantFinishDoesNotDeadlock(t *testing.T) {
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, conn, nil)
	const flowID = uint64(120)
	forceSend := make(chan struct{})
	var forceOnce sync.Once
	forceRelease := func() { forceOnce.Do(func() { close(forceSend) }) }
	defer forceRelease()
	sendStarted := make(chan struct{})
	retireDone := make(chan struct{})
	forcedErr := errors.New("forced reentrant ACK release")

	flow := newCompactUDPFlow(session, flowID, "reentrant-ack.example:53", wire.CarrierUDP)
	defer flow.shutdown(net.ErrClosed)
	var entry *compactUDPEntry
	ack := &compactGenerationLease{
		flowID: flowID,
		send: func([]byte) error {
			close(sendStarted)
			go func() {
				session.finishCompactEntry(entry, net.ErrClosed, false)
				close(retireDone)
			}()
			select {
			case <-retireDone:
				return nil
			case <-forceSend:
				return forcedErr
			}
		},
	}
	entry = &compactUDPEntry{
		flowID:    flowID,
		target:    flow.target,
		downlink:  flow.downlink,
		lease:     ack,
		symmetric: flow,
	}
	if !session.reserveCompactEntry(entry) {
		t.Fatal("reentrant Compact entry reservation failed")
	}
	stopCompactIdle(flow)
	ackDone := make(chan error, 1)
	go func() { ackDone <- ack.SendOpenAck() }()
	select {
	case <-sendStarted:
	case <-time.After(time.Second):
		t.Fatal("reentrant SendDatagram did not start")
	}
	select {
	case err := <-ackDone:
		if !errors.Is(err, errCompactAckRevoked) {
			t.Fatalf("reentrant ACK error = %v, want errCompactAckRevoked", err)
		}
	case <-time.After(250 * time.Millisecond):
		forceRelease()
		<-ackDone
		<-retireDone
		t.Fatal("reentrant Compact finish deadlocked ACK send")
	}
	select {
	case <-retireDone:
	case <-time.After(time.Second):
		t.Fatal("reentrant Compact finish did not return")
	}
	if ack.Acked() {
		t.Fatal("reentrantly revoked ACK was marked acknowledged")
	}
}

func TestCompactRepeatedOpenMatchingDeliversEveryPayload(t *testing.T) {
	routes := make(chan packetRoute, 1)
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{}, conn, routes)
	const flowID = uint64(101)
	const target = "repeat.example:53"

	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierTCP, target, []byte("one")))
	waitForCompactState(t, func() bool {
		records, pending, _ := udpPairManagerCounts(session.Handler.pairing, session.ID)
		return records == 1 && pending == 1
	}, "asymmetric Compact OPEN did not enter waiting pair state")
	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierTCP, target, []byte("two")))
	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierTCP, target, []byte("three")))

	_, attach := udpPairHeaders(flowID)
	if err := session.Handler.submitAndRouteUDP(context.Background(), session.Source, session.ID, attach, target, udpHalf{Role: wire.FlowRoleAttach, Downlink: newUDPPairTestDownlink()}); err != nil {
		t.Fatal(err)
	}
	route := awaitPacketRoute(t, routes)
	for _, want := range []string{"one", "two", "three"} {
		if got := string(readPacket(t, route.conn)); got != want {
			t.Fatalf("asymmetric repeated payload = %q, want %q", got, want)
		}
	}
	_ = route.conn.Close()
}

func TestCompactRepeatedOpenAfterAckResendsAck(t *testing.T) {
	routes := make(chan packetRoute, 1)
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{}, conn, routes)
	const flowID = uint64(102)
	const target = "ack-repeat.example:53"

	route, _ := activateCompactAsymmetric(t, session, routes, flowID, target, []byte("first"))
	_ = readPacket(t, route.conn)
	_ = awaitCompactFrame(t, conn.sent, wire.UDPTypeOpenAck, flowID)

	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierTCP, target, []byte("second")))
	_ = awaitCompactFrame(t, conn.sent, wire.UDPTypeOpenAck, flowID)
	if got := string(readPacket(t, route.conn)); got != "second" {
		t.Fatalf("repeated asymmetric payload = %q, want second", got)
	}
	_ = route.conn.Close()
}

func TestCompactAckSendFailureDoesNotMarkAcked(t *testing.T) {
	wantErr := errors.New("send ack failed")
	ack := &compactGenerationLease{
		flowID: 103,
		send: func([]byte) error {
			return wantErr
		},
	}
	if !ack.bind(1) {
		t.Fatal("Compact ACK test state did not bind")
	}
	if err := ack.SendOpenAck(); !errors.Is(err, wantErr) {
		t.Fatalf("SendOpenAck error = %v, want %v", err, wantErr)
	}
	if ack.Acked() {
		t.Fatal("failed OPEN_ACK send marked the state acknowledged")
	}
}

func TestCompactAckSendFailureRemovesSymmetricEntry(t *testing.T) {
	routes := make(chan packetRoute, 1)
	conn := newCompactTestQuicConn()
	conn.sendErr = errors.New("symmetric ack failed")
	conn.failCount = -1
	session := newCompactTestSession(t, Limits{}, conn, routes)
	const flowID = uint64(104)

	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierUDP, "symmetric-fail.example:53", []byte("payload")))
	if entry := session.getCompactEntry(flowID); entry != nil {
		t.Fatalf("failed symmetric ACK left Compact entry %+v", entry)
	}
	if active := sessionUDPActiveFlows(session); active != 0 {
		t.Fatalf("active flows after failed symmetric ACK = %d, want 0", active)
	}
	select {
	case route := <-routes:
		_ = route.conn.Close()
		t.Fatal("failed symmetric ACK still routed the flow")
	default:
	}
}

func TestCompactAckSendFailureRemovesAsymmetricPair(t *testing.T) {
	routes := make(chan packetRoute, 1)
	conn := newCompactTestQuicConn()
	conn.sendErr = errors.New("asymmetric ack failed")
	conn.failCount = -1
	session := newCompactTestSession(t, Limits{}, conn, routes)
	const flowID = uint64(105)
	const target = "asymmetric-fail.example:53"

	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierTCP, target, []byte("payload")))
	waitForCompactState(t, func() bool {
		records, pending, _ := udpPairManagerCounts(session.Handler.pairing, session.ID)
		return records == 1 && pending == 1
	}, "asymmetric Compact OPEN did not enter waiting pair state")
	entry := session.getCompactEntry(flowID)
	if entry == nil || entry.pair == nil || entry.lease == nil {
		t.Fatalf("asymmetric Compact entry = %+v, want pair and ACK state", entry)
	}

	_, attach := udpPairHeaders(flowID)
	downlink := newUDPPairTestDownlink()
	if err := session.Handler.submitAndRouteUDP(context.Background(), session.Source, session.ID, attach, target, udpHalf{Role: wire.FlowRoleAttach, Downlink: downlink}); err != nil {
		t.Fatal(err)
	}
	route := awaitPacketRoute(t, routes)
	buffer := make([]byte, 64)
	if _, _, err := route.conn.ReadFrom(buffer); !errors.Is(err, conn.sendErr) {
		t.Fatalf("ReadFrom ACK failure = %v, want %v", err, conn.sendErr)
	}
	if entry.lease.Acked() {
		t.Fatal("failed asymmetric OPEN_ACK marked the state acknowledged")
	}
	waitForCompactState(t, func() bool {
		records, _, _ := udpPairManagerCounts(session.Handler.pairing, session.ID)
		return session.getCompactEntry(flowID) == nil && records == 0
	}, "failed asymmetric ACK left Compact entry or pair record")
	if downlink.closeCount.Load() != 1 {
		t.Fatalf("downlink close count = %d, want 1", downlink.closeCount.Load())
	}
}

func TestCompactRepeatedOpenTargetConflictClosesFlow(t *testing.T) {
	routes := make(chan packetRoute, 1)
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{}, conn, routes)
	const flowID = uint64(106)

	route, _ := activateCompactAsymmetric(t, session, routes, flowID, "first.example:53", []byte("accepted"))
	if got := string(readPacket(t, route.conn)); got != "accepted" {
		t.Fatalf("accepted payload = %q", got)
	}
	_ = awaitCompactFrame(t, conn.sent, wire.UDPTypeOpenAck, flowID)

	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierTCP, "second.example:53", []byte("conflict")))
	_ = awaitCompactFrame(t, conn.sent, wire.UDPTypeCompactClose, flowID)
	if entry := session.getCompactEntry(flowID); entry != nil {
		t.Fatalf("target conflict left entry %+v", entry)
	}
	if records, pending, sessionPending := udpPairManagerCounts(session.Handler.pairing, session.ID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("after target conflict records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
	if err := route.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := route.conn.ReadFrom(make([]byte, 32)); err == nil {
		t.Fatal("conflicting target payload entered the old asymmetric flow")
	}
}

func TestCompactRepeatedOpenDownlinkConflictClosesFlow(t *testing.T) {
	routes := make(chan packetRoute, 1)
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{}, conn, routes)
	const flowID = uint64(107)
	const target = "downlink-conflict.example:53"

	route, _ := activateCompactAsymmetric(t, session, routes, flowID, target, []byte("accepted"))
	_ = readPacket(t, route.conn)
	_ = awaitCompactFrame(t, conn.sent, wire.UDPTypeOpenAck, flowID)

	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierUDP, target, []byte("conflict")))
	_ = awaitCompactFrame(t, conn.sent, wire.UDPTypeCompactClose, flowID)
	if entry := session.getCompactEntry(flowID); entry != nil {
		t.Fatalf("downlink conflict left entry %+v", entry)
	}
	if records, pending, sessionPending := udpPairManagerCounts(session.Handler.pairing, session.ID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("after downlink conflict records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
	if err := route.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := route.conn.ReadFrom(make([]byte, 32)); err == nil {
		t.Fatal("conflicting downlink payload entered the old asymmetric flow")
	}
}

func TestCompactDataUnknownSendsClose(t *testing.T) {
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{}, conn, nil)
	const flowID = uint64(108)

	session.handleCompactFrame(context.Background(), compactControlFrame(t, wire.UDPTypeData, flowID, []byte("unknown")))
	_ = awaitCompactFrame(t, conn.sent, wire.UDPTypeCompactClose, flowID)
}

func TestCompactCloseCancelsWaitingAsymmetricPair(t *testing.T) {
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{}, conn, nil)
	const flowID = uint64(109)

	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierTCP, "waiting-close.example:53", []byte("payload")))
	waitForCompactState(t, func() bool {
		records, pending, _ := udpPairManagerCounts(session.Handler.pairing, session.ID)
		return records == 1 && pending == 1
	}, "asymmetric pair did not enter waiting state")
	entry := session.getCompactEntry(flowID)
	if entry == nil || entry.pair == nil {
		t.Fatalf("waiting entry = %+v, want pair handle", entry)
	}

	session.handleCompactFrame(context.Background(), compactControlFrame(t, wire.UDPTypeCompactClose, flowID, nil))
	if current := session.getCompactEntry(flowID); current != nil {
		t.Fatalf("Compact CLOSE left entry %+v", current)
	}
	if records, pending, sessionPending := udpPairManagerCounts(session.Handler.pairing, session.ID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("after waiting close records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
	select {
	case <-entry.pair.Done():
	default:
		t.Fatal("Compact CLOSE did not cancel the waiting pair")
	}
}

func TestCompactCloseCancelsActiveAsymmetricPair(t *testing.T) {
	routes := make(chan packetRoute, 1)
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{}, conn, routes)
	const flowID = uint64(110)
	const target = "active-close.example:53"

	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierTCP, target, []byte("payload")))
	waitForCompactState(t, func() bool {
		records, pending, _ := udpPairManagerCounts(session.Handler.pairing, session.ID)
		return records == 1 && pending == 1
	}, "asymmetric pair did not enter waiting state")
	_, attach := udpPairHeaders(flowID)
	downlink := newUDPPairTestDownlink()
	if err := session.Handler.submitAndRouteUDP(context.Background(), session.Source, session.ID, attach, target, udpHalf{Role: wire.FlowRoleAttach, Downlink: downlink}); err != nil {
		t.Fatal(err)
	}
	route := awaitPacketRoute(t, routes)
	waitForCompactState(t, func() bool {
		records, pending, _ := udpPairManagerCounts(session.Handler.pairing, session.ID)
		return records == 1 && pending == 0
	}, "asymmetric pair did not become active")

	session.handleCompactFrame(context.Background(), compactControlFrame(t, wire.UDPTypeCompactClose, flowID, nil))
	if current := session.getCompactEntry(flowID); current != nil {
		t.Fatalf("active Compact CLOSE left entry %+v", current)
	}
	if records, pending, sessionPending := udpPairManagerCounts(session.Handler.pairing, session.ID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("after active close records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
	if err := route.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := route.conn.ReadFrom(make([]byte, 1)); err == nil {
		t.Fatal("active paired conn remained readable after Compact CLOSE")
	}
	if downlink.closeCount.Load() != 1 {
		t.Fatalf("downlink close count = %d, want 1", downlink.closeCount.Load())
	}
}

func TestCompactUnknownCloseIsIdempotent(t *testing.T) {
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{}, conn, nil)
	frame := compactControlFrame(t, wire.UDPTypeCompactClose, 111, nil)

	session.handleCompactFrame(context.Background(), frame)
	session.handleCompactFrame(context.Background(), frame)
	if active := sessionUDPActiveFlows(session); active != 0 {
		t.Fatalf("unknown close changed active flow count to %d", active)
	}
	assertNoCompactFrame(t, conn.sent)
}

func TestCompactOldFinishCannotRemoveReusedFlowID(t *testing.T) {
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, conn, nil)
	const flowID = uint64(112)

	oldFlow := newCompactUDPFlow(session, flowID, "old-finish.example:53", wire.CarrierUDP)
	oldEntry := &compactUDPEntry{
		flowID:    flowID,
		target:    oldFlow.target,
		downlink:  oldFlow.downlink,
		lease:     &compactGenerationLease{flowID: flowID, send: session.SendDatagram},
		symmetric: oldFlow,
	}
	if !session.reserveCompactEntry(oldEntry) {
		t.Fatal("old Compact entry reservation failed")
	}
	stopCompactIdle(oldFlow)
	if _, ok := session.detachCompactEntry(flowID, oldEntry.generation); !ok {
		t.Fatal("old Compact entry detach failed")
	}

	newFlow := newCompactUDPFlow(session, flowID, "new-finish.example:53", wire.CarrierUDP)
	newEntry := &compactUDPEntry{
		flowID:    flowID,
		target:    newFlow.target,
		downlink:  newFlow.downlink,
		lease:     &compactGenerationLease{flowID: flowID, send: session.SendDatagram},
		symmetric: newFlow,
	}
	if !session.reserveCompactEntry(newEntry) {
		t.Fatal("reused Compact entry reservation failed")
	}
	if newEntry.generation == oldEntry.generation {
		t.Fatalf("reused generation = old generation %d", oldEntry.generation)
	}

	session.finishCompactEntry(oldEntry, io.EOF, false)
	session.handleCompactFrame(context.Background(), compactControlFrame(t, wire.UDPTypeData, flowID, []byte("new-data")))
	if got := string(readPacket(t, newFlow)); got != "new-data" {
		t.Fatalf("new generation payload = %q, want new-data", got)
	}
	if current := session.getCompactEntry(flowID); current != newEntry {
		t.Fatalf("old finish removed reused entry: %+v", current)
	}
	newFlow.shutdown(net.ErrClosed)
}

func TestCompactAsymmetricPairTransitionDoesNotDoubleCountQuota(t *testing.T) {
	routes := make(chan packetRoute, 1)
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, conn, routes)
	const flowID = uint64(113)
	const target = "quota-pair.example:53"

	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierTCP, target, []byte("payload")))
	waitForCompactState(t, func() bool {
		records, pending, _ := udpPairManagerCounts(session.Handler.pairing, session.ID)
		return records == 1 && pending == 1
	}, "asymmetric pair did not enter waiting state")
	if active := sessionUDPActiveFlows(session); active != 1 {
		t.Fatalf("active flows while waiting = %d, want 1", active)
	}

	_, attach := udpPairHeaders(flowID)
	if err := session.Handler.submitAndRouteUDP(context.Background(), session.Source, session.ID, attach, target, udpHalf{Role: wire.FlowRoleAttach, Downlink: newUDPPairTestDownlink()}); err != nil {
		t.Fatal(err)
	}
	route := awaitPacketRoute(t, routes)
	if active := sessionUDPActiveFlows(session); active != 1 {
		t.Fatalf("active flows after pair transition = %d, want 1", active)
	}
	if records, pending, _ := udpPairManagerCounts(session.Handler.pairing, session.ID); records != 1 || pending != 0 {
		t.Fatalf("after pair transition records=%d pending=%d", records, pending)
	}
	_ = route.conn.Close()
	waitForCompactState(t, func() bool { return sessionUDPActiveFlows(session) == 0 }, "pair close did not release Compact quota")
}

func TestPortalSessionCloseCancelsAllUDPState(t *testing.T) {
	routes := make(chan packetRoute, 2)
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 4, QUICQueueBytes: 256, QUICQueuePackets: 4}, conn, routes)

	session.handleCompactFrame(context.Background(), compactOpenFrame(t, 114, wire.CarrierUDP, "session-symmetric.example:53", []byte("symmetric")))
	symmetricRoute := awaitPacketRoute(t, routes)
	_ = awaitCompactFrame(t, conn.sent, wire.UDPTypeOpenAck, 114)
	session.handleCompactFrame(context.Background(), compactOpenFrame(t, 115, wire.CarrierTCP, "session-asymmetric.example:53", []byte("asymmetric")))
	waitForCompactState(t, func() bool {
		records, pending, _ := udpPairManagerCounts(session.Handler.pairing, session.ID)
		return records == 1 && pending == 1
	}, "session asymmetric pair did not enter waiting state")
	session.handleLegacyDatagram(context.Background(), &wire.UDPMessage{Type: wire.UDPTypeRequest, FlowID: 116, Target: "session-legacy.example:53", Payload: []byte("legacy")})
	legacyRoute := awaitPacketRoute(t, routes)

	session.Close()

	session.mu.Lock()
	compactCount := len(session.udp.compact)
	legacyCount := len(session.udp.legacy)
	active := session.udp.activeFlows
	queued := session.queuedBytes
	session.mu.Unlock()
	if compactCount != 0 || legacyCount != 0 || active != 0 || queued != 0 {
		t.Fatalf("after session close compact=%d legacy=%d active=%d queued=%d", compactCount, legacyCount, active, queued)
	}
	if records, pending, sessionPending := udpPairManagerCounts(session.Handler.pairing, session.ID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("after session close records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
	for name, pc := range map[string]net.PacketConn{"symmetric": symmetricRoute.conn, "legacy": legacyRoute.conn} {
		if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := pc.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("%s ReadFrom after session close = %v, want net.ErrClosed", name, err)
		}
	}
	if conn.closeWithErrorCalls.Load() != 1 {
		t.Fatalf("QUIC CloseWithError calls = %d, want 1", conn.closeWithErrorCalls.Load())
	}
}

func stageCompactAsymmetricForTest(t *testing.T, session *portalSession, flowID uint64, target string, payload []byte) *compactUDPEntry {
	t.Helper()
	ack := &compactGenerationLease{flowID: flowID, send: session.SendDatagram}
	uplink := newQUICUDPUplink(session)
	header := wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		FlowID:   flowID,
		Kind:     wire.FlowKindUDP,
		Uplink:   wire.CarrierUDP,
		Downlink: wire.CarrierTCP,
	}
	half := udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink, compactLease: ack}
	handle, err := session.Handler.pairing.stageUDPWithSource(context.Background(), session.ID, header, target, half, session.Source, udpHalfTransport(header, half))
	if err != nil {
		t.Fatal(err)
	}
	entry := &compactUDPEntry{flowID: flowID, target: target, downlink: wire.CarrierTCP, lease: ack, pair: handle}
	if !session.reserveCompactEntry(entry) {
		session.Handler.pairing.finishUDP(handle, errCompactFlowRejected)
		t.Fatal("staged Compact entry reservation failed")
	}
	if !session.Handler.pairing.setUDPFinish(handle, func(cause error) {
		session.finishCompactEntry(entry, cause, true)
	}) {
		t.Fatal("staged Compact finish callback installation failed")
	}
	if !entry.deliver(payload) {
		t.Fatal("staged Compact payload delivery failed")
	}
	return entry
}

func pairedIdleStarted(conn *pairedUDPConn) bool {
	conn.idleMu.Lock()
	defer conn.idleMu.Unlock()
	return conn.idle != nil
}

func TestCompactAsymmetricAdmissionBlocksRouteUntilEntryReserved(t *testing.T) {
	routes := make(chan packetRoute, 1)
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, conn, routes)
	holder := newLegacyUDPFlow(session, legacyUDPKey{flowID: 201, target: "quota-holder.example:53"})
	if !session.reserveLegacyFlow(holder) {
		t.Fatal("quota holder reservation failed")
	}
	const flowID = uint64(202)
	const target = "admission-window.example:53"
	frame := compactOpenFrame(t, flowID, wire.CarrierTCP, target, []byte("payload"))

	session.mu.Lock()
	locked := true
	defer func() {
		if locked {
			session.mu.Unlock()
		}
	}()
	openDone := make(chan struct{})
	go func() {
		session.openAsymmetricCompact(context.Background(), frame)
		close(openDone)
	}()
	waitForCompactState(t, func() bool {
		records, pending, _ := udpPairManagerCounts(session.Handler.pairing, session.ID)
		return records == 1 && pending == 1
	}, "Compact OPEN did not reach the Submit/reserve window")

	_, attach := udpPairHeaders(flowID)
	downlink := newUDPPairTestDownlink()
	attachDone := make(chan error, 1)
	go func() {
		attachDone <- session.Handler.submitAndRouteUDP(context.Background(), session.Source, session.ID, attach, target, udpHalf{Role: wire.FlowRoleAttach, Downlink: downlink})
	}()
	select {
	case err := <-attachDone:
		if err != nil {
			t.Errorf("complementary half submit: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("complementary half remained blocked in the admission window")
	}

	var routedBeforeAdmission net.PacketConn
	select {
	case route := <-routes:
		routedBeforeAdmission = route.conn
	default:
	}
	session.mu.Unlock()
	locked = false
	select {
	case <-openDone:
	case <-time.After(time.Second):
		t.Fatal("Compact OPEN did not finish after releasing the reservation barrier")
	}
	if routedBeforeAdmission != nil {
		_ = routedBeforeAdmission.Close()
		holder.shutdown(net.ErrClosed)
		t.Fatal("Upstream received asymmetric flow before Compact entry/quota admission")
	}
	select {
	case route := <-routes:
		_ = route.conn.Close()
		holder.shutdown(net.ErrClosed)
		t.Fatal("Upstream received asymmetric flow after Compact admission failed")
	default:
	}
	if entry := session.getCompactEntry(flowID); entry != nil {
		t.Fatalf("failed admission left Compact entry %+v", entry)
	}
	if records, pending, sessionPending := udpPairManagerCounts(session.Handler.pairing, session.ID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("failed admission left records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
	holder.shutdown(net.ErrClosed)
}

func TestPairedUDPConnIdleStartsOnlyAfterManagerBind(t *testing.T) {
	t.Run("live bind", func(t *testing.T) {
		manager := newFlowPairManager(time.Second)
		defer manager.Close()
		handle, paired, _, _ := completeUDPPair(t, manager, wire.SessionID{31}, 203)
		paired.IdleTimeout = time.Second
		conn := newPairedUDPConn(paired)
		if pairedIdleStarted(conn) {
			t.Fatal("paired UDP constructor started idle timer before manager bind")
		}
		conn.setFinish(func(cause error) { manager.finishUDP(handle, cause) })
		if !manager.bindUDP(handle, conn) {
			t.Fatal("bindUDP rejected live pair")
		}
		if !pairedIdleStarted(conn) {
			t.Fatal("manager bind did not start idle timer after active publication")
		}
		manager.finishUDP(handle, net.ErrClosed)
	})

	t.Run("canceled before bind", func(t *testing.T) {
		manager := newFlowPairManager(time.Second)
		defer manager.Close()
		handle, paired, _, _ := completeUDPPair(t, manager, wire.SessionID{32}, 204)
		paired.IdleTimeout = time.Nanosecond
		conn := newPairedUDPConn(paired)
		conn.setFinish(func(cause error) { manager.finishUDP(handle, cause) })
		manager.finishUDP(handle, context.Canceled)
		if manager.bindUDP(handle, conn) {
			t.Fatal("bindUDP accepted canceled pair")
		}
		if pairedIdleStarted(conn) {
			t.Fatal("bind failure started paired UDP idle timer")
		}
	})
}

func TestPairedUDPConnImmediateIdleUsesManagerFirstFinish(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	sessionID := wire.SessionID{33}
	flowID := uint64(205)
	open, attach := udpPairHeaders(flowID)
	uplink := newUDPPairTestUplink()
	handle, _, err := manager.SubmitUDP(context.Background(), sessionID, open, "immediate-idle.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink})
	if err != nil {
		t.Fatal(err)
	}
	physicalClose := make(chan bool, 1)
	downlink := newUDPPairTestDownlink()
	downlink.onClose = func() {
		records, _, _ := udpPairManagerCounts(manager, sessionID)
		physicalClose <- records != 0
	}
	_, paired, err := manager.SubmitUDP(context.Background(), sessionID, attach, "immediate-idle.example:53", udpHalf{Role: wire.FlowRoleAttach, Downlink: downlink})
	if err != nil || paired == nil {
		t.Fatalf("complete pair = (%v, %v)", paired, err)
	}
	paired.IdleTimeout = time.Nanosecond
	conn := newPairedUDPConn(paired)
	if pairedIdleStarted(conn) {
		t.Fatal("constructor started immediate idle before bind")
	}
	conn.setFinish(func(cause error) { manager.finishUDP(handle, cause) })
	if !manager.bindUDP(handle, conn) {
		t.Fatal("bindUDP rejected immediate-idle pair")
	}
	select {
	case sawRecord := <-physicalClose:
		if sawRecord {
			t.Fatal("physical close observed active manager record during immediate idle")
		}
	case <-time.After(time.Second):
		t.Fatal("immediate idle did not close paired UDP conn")
	}
}

func TestCompactCloseCancelsPairedBeforeBind(t *testing.T) {
	for _, test := range []struct {
		name  string
		admit bool
	}{
		{name: "staged paired"},
		{name: "admitted before bind", admit: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			routes := make(chan packetRoute, 1)
			session := newCompactTestSession(t, Limits{}, newCompactTestQuicConn(), routes)
			flowID := uint64(206)
			target := "paired-close.example:53"
			entry := stageCompactAsymmetricForTest(t, session, flowID, target, []byte("payload"))
			_, attach := udpPairHeaders(flowID)
			_, returnedPair, err := session.Handler.pairing.SubmitUDP(context.Background(), session.ID, attach, target, udpHalf{Role: wire.FlowRoleAttach, Downlink: newUDPPairTestDownlink()})
			if err != nil {
				t.Fatal(err)
			}
			if returnedPair != nil {
				t.Fatal("staged pair escaped to complementary caller before admission")
			}
			var pendingConn *pairedUDPConn
			if test.admit {
				paired, ok := session.Handler.pairing.admitUDP(entry.pair)
				if !ok || paired == nil {
					t.Fatalf("admitUDP = (%v, %v), want completed pair", paired, ok)
				}
				paired.IdleTimeout = time.Second
				pendingConn = newPairedUDPConn(paired)
				pendingConn.setFinish(func(cause error) { session.Handler.pairing.finishUDP(entry.pair, cause) })
				if pairedIdleStarted(pendingConn) {
					t.Fatal("pre-bind conn started idle timer")
				}
			}

			session.handleCompactFrame(context.Background(), compactControlFrame(t, wire.UDPTypeCompactClose, flowID, nil))
			if current := session.getCompactEntry(flowID); current != nil {
				t.Fatalf("paired/binding close left entry %+v", current)
			}
			if records, pending, sessionPending := udpPairManagerCounts(session.Handler.pairing, session.ID); records != 0 || pending != 0 || sessionPending != 0 {
				t.Fatalf("paired/binding close left records=%d pending=%d session_pending=%d", records, pending, sessionPending)
			}
			if pendingConn != nil {
				if session.Handler.pairing.bindUDP(entry.pair, pendingConn) {
					t.Fatal("bindUDP activated pair after Compact CLOSE")
				}
				if pairedIdleStarted(pendingConn) {
					t.Fatal("stale bind started idle timer after Compact CLOSE")
				}
			}
			select {
			case route := <-routes:
				_ = route.conn.Close()
				t.Fatal("paired/binding Compact CLOSE still routed upstream")
			default:
			}
		})
	}
}

func TestCompactAsymmetricOldManagerFinishCannotRemoveReusedFlowID(t *testing.T) {
	session := newCompactTestSession(t, Limits{QUICFlowsPerSession: 1}, newCompactTestQuicConn(), nil)
	const flowID = uint64(207)
	const target = "aba-asymmetric.example:53"

	ack := &compactGenerationLease{flowID: flowID, send: session.SendDatagram}
	oldUplink := newQUICUDPUplink(session)
	open, _ := udpPairHeaders(flowID)
	oldHandle, err := session.Handler.pairing.stageUDPWithSource(context.Background(), session.ID, open, target, udpHalf{Role: wire.FlowRoleOpen, Uplink: oldUplink, compactLease: ack}, session.Source, "udp")
	if err != nil {
		t.Fatal(err)
	}
	oldEntry := &compactUDPEntry{flowID: flowID, target: target, downlink: wire.CarrierTCP, lease: ack, pair: oldHandle}
	if !session.reserveCompactEntry(oldEntry) {
		t.Fatal("old asymmetric entry reservation failed")
	}
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	if !session.Handler.pairing.setUDPFinish(oldHandle, func(cause error) {
		close(callbackStarted)
		<-releaseCallback
		session.finishCompactEntry(oldEntry, cause, true)
	}) {
		t.Fatal("old manager finish callback installation failed")
	}
	finishDone := make(chan struct{})
	go func() {
		session.Handler.pairing.finishUDP(oldHandle, io.EOF)
		close(finishDone)
	}()
	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("old manager onFinish callback did not start")
	}
	if _, ok := session.detachCompactEntry(flowID, oldEntry.generation); !ok {
		t.Fatal("old entry detach failed during ABA setup")
	}

	newEntry := stageCompactAsymmetricForTest(t, session, flowID, target, []byte("new-open"))
	close(releaseCallback)
	select {
	case <-finishDone:
	case <-time.After(time.Second):
		t.Fatal("old manager finish did not complete")
	}
	if current := session.getCompactEntry(flowID); current != newEntry {
		t.Fatalf("old asymmetric manager callback removed reused entry: %+v", current)
	}
	if records, pending, _ := udpPairManagerCounts(session.Handler.pairing, session.ID); records != 1 || pending != 1 {
		t.Fatalf("reused asymmetric manager state records=%d pending=%d", records, pending)
	}
	session.handleCompactFrame(context.Background(), compactControlFrame(t, wire.UDPTypeData, flowID, []byte("new-data")))
	newUplink, ok := newEntry.pair.record.open.Uplink.(*quicUDPUplink)
	if !ok {
		t.Fatalf("reused uplink type = %T", newEntry.pair.record.open.Uplink)
	}
	if err := newUplink.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"new-open", "new-data"} {
		payload, err := newUplink.ReadPacket()
		if err != nil {
			t.Fatal(err)
		}
		if got := string(payload); got != want {
			t.Fatalf("reused asymmetric payload = %q, want %q", got, want)
		}
	}
}

func TestCompactRepeatedAckResendFailureRemovesExactPair(t *testing.T) {
	routes := make(chan packetRoute, 1)
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{}, conn, routes)
	const flowID = uint64(208)
	const target = "ack-resend-failure.example:53"
	route, downlink := activateCompactAsymmetric(t, session, routes, flowID, target, []byte("first"))
	entry := session.getCompactEntry(flowID)
	if entry == nil || entry.pair == nil || entry.lease == nil {
		t.Fatalf("active entry = %+v", entry)
	}
	_ = readPacket(t, route.conn)
	_ = awaitCompactFrame(t, conn.sent, wire.UDPTypeOpenAck, flowID)
	conn.mu.Lock()
	conn.sendErr = errors.New("repeated ACK resend failed")
	conn.failCount = 1
	conn.mu.Unlock()

	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierTCP, target, []byte("second")))
	if current := session.getCompactEntry(flowID); current != nil {
		t.Fatalf("repeated ACK failure left entry %+v", current)
	}
	if records, pending, sessionPending := udpPairManagerCounts(session.Handler.pairing, session.ID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("repeated ACK failure left records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
	select {
	case <-entry.pair.Done():
	default:
		t.Fatal("repeated ACK failure did not finish exact pair")
	}
	if downlink.closeCount.Load() != 1 {
		t.Fatalf("repeated ACK failure downlink close count = %d, want 1", downlink.closeCount.Load())
	}
}

func TestCompactDownlinkAckFailureRemovesExactPair(t *testing.T) {
	routes := make(chan packetRoute, 1)
	conn := newCompactTestQuicConn()
	session := newCompactTestSession(t, Limits{}, conn, routes)
	const flowID = uint64(209)
	const target = "downlink-ack-failure.example:53"

	session.handleCompactFrame(context.Background(), compactOpenFrame(t, flowID, wire.CarrierTCP, target, []byte("payload")))
	waitForCompactState(t, func() bool {
		records, pending, _ := udpPairManagerCounts(session.Handler.pairing, session.ID)
		return records == 1 && pending == 1
	}, "downlink ACK test did not enter waiting state")
	entry := session.getCompactEntry(flowID)
	_, attach := udpPairHeaders(flowID)
	ackErr := errors.New("downlink WriteAck failed")
	downlink := newUDPPairTestDownlink()
	downlink.ackErr = ackErr
	if err := session.Handler.submitAndRouteUDP(context.Background(), session.Source, session.ID, attach, target, udpHalf{Role: wire.FlowRoleAttach, Downlink: downlink}); err != nil {
		t.Fatal(err)
	}
	route := awaitPacketRoute(t, routes)
	if _, _, err := route.conn.ReadFrom(make([]byte, 64)); !errors.Is(err, ackErr) {
		t.Fatalf("ReadFrom downlink ACK failure = %v, want %v", err, ackErr)
	}
	if entry.lease.Acked() {
		t.Fatal("downlink ACK failure marked Compact ACK state")
	}
	if current := session.getCompactEntry(flowID); current != nil {
		t.Fatalf("downlink ACK failure left entry %+v", current)
	}
	if records, pending, sessionPending := udpPairManagerCounts(session.Handler.pairing, session.ID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("downlink ACK failure left records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
	if downlink.closeCount.Load() != 1 {
		t.Fatalf("downlink ACK failure close count = %d, want 1", downlink.closeCount.Load())
	}
}
