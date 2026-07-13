package server

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

type udpPairTestUplink struct {
	packets     chan []byte
	readStarted chan struct{}
	closed      chan struct{}
	readOnce    sync.Once
	closeOnce   sync.Once
	closeCount  atomic.Int32
}

func newUDPPairTestUplink() *udpPairTestUplink {
	return &udpPairTestUplink{
		packets:     make(chan []byte, 8),
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
}

func (u *udpPairTestUplink) Deliver(payload []byte) {
	copyPayload := append([]byte(nil), payload...)
	select {
	case <-u.closed:
		return
	default:
	}
	select {
	case u.packets <- copyPayload:
	case <-u.closed:
	}
}

func (u *udpPairTestUplink) ReadPacket() ([]byte, error) {
	u.readOnce.Do(func() { close(u.readStarted) })
	select {
	case payload := <-u.packets:
		return payload, nil
	case <-u.closed:
		return nil, io.EOF
	}
}

func (u *udpPairTestUplink) SetReadDeadline(time.Time) error { return nil }

func (u *udpPairTestUplink) Close() error {
	u.closeOnce.Do(func() {
		u.closeCount.Add(1)
		close(u.closed)
	})
	return nil
}

type udpPairTestDownlink struct {
	closed     chan struct{}
	closeOnce  sync.Once
	closeCount atomic.Int32
	ackErr     error
	onClose    func()
}

func newUDPPairTestDownlink() *udpPairTestDownlink {
	return &udpPairTestDownlink{closed: make(chan struct{})}
}

func (d *udpPairTestDownlink) WritePacket([]byte) error { return nil }
func (d *udpPairTestDownlink) WriteAck(uint64) error    { return d.ackErr }
func (d *udpPairTestDownlink) WriteClose(uint64) error  { return nil }
func (d *udpPairTestDownlink) Close() error {
	d.closeOnce.Do(func() {
		if d.onClose != nil {
			d.onClose()
		}
		d.closeCount.Add(1)
		close(d.closed)
	})
	return nil
}

type blockingUDPWriteConn struct {
	writeStarted chan struct{}
	closed       chan struct{}
	release      chan struct{}
	writeOnce    sync.Once
	closeOnce    sync.Once
	releaseOnce  sync.Once
	closeCount   atomic.Int32
}

func newBlockingUDPWriteConn() *blockingUDPWriteConn {
	return &blockingUDPWriteConn{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
		release:      make(chan struct{}),
	}
}

func (c *blockingUDPWriteConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *blockingUDPWriteConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	<-c.release
	return 0, net.ErrClosed
}
func (c *blockingUDPWriteConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeCount.Add(1)
		close(c.closed)
		c.releaseOnce.Do(func() { close(c.release) })
	})
	return nil
}
func (c *blockingUDPWriteConn) forceRelease() {
	c.releaseOnce.Do(func() { close(c.release) })
}
func (c *blockingUDPWriteConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *blockingUDPWriteConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *blockingUDPWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingUDPWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingUDPWriteConn) SetWriteDeadline(time.Time) error { return nil }

func udpPairHeaders(flowID uint64) (wire.FlowHeader, wire.FlowHeader) {
	open := wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		FlowID:   flowID,
		Kind:     wire.FlowKindUDP,
		Uplink:   wire.CarrierUDP,
		Downlink: wire.CarrierTCP,
	}
	attach := open
	attach.Role = wire.FlowRoleAttach
	return open, attach
}

func completeUDPPair(t *testing.T, manager *flowPairManager, sessionID wire.SessionID, flowID uint64) (*udpPairHandle, *pairedUDP, *udpPairTestUplink, *udpPairTestDownlink) {
	t.Helper()
	open, attach := udpPairHeaders(flowID)
	uplink := newUDPPairTestUplink()
	handle, paired, err := manager.SubmitUDP(context.Background(), sessionID, open, "pair.example:53", udpHalf{
		Role:   wire.FlowRoleOpen,
		Uplink: uplink,
	})
	if err != nil || handle == nil || paired != nil {
		t.Fatalf("SubmitUDP(open) = (%v, %v, %v), want (handle, nil, nil)", handle, paired, err)
	}
	downlink := newUDPPairTestDownlink()
	secondHandle, paired, err := manager.SubmitUDP(context.Background(), sessionID, attach, "pair.example:53", udpHalf{
		Role:     wire.FlowRoleAttach,
		Downlink: downlink,
	})
	if err != nil || paired == nil {
		t.Fatalf("SubmitUDP(attach) = (%v, %v, %v), want completed pair", secondHandle, paired, err)
	}
	if secondHandle != handle {
		t.Fatal("pair completion returned a different handle")
	}
	return handle, paired, uplink, downlink
}

func bindUDPPair(t *testing.T, manager *flowPairManager, handle *udpPairHandle, paired *pairedUDP) *pairedUDPConn {
	t.Helper()
	conn := newPairedUDPConn(paired)
	conn.setFinish(func(err error) { manager.finishUDP(handle, err) })
	if !manager.bindUDP(handle, conn) {
		t.Fatal("bindUDP rejected a live completed pair")
	}
	return conn
}

func udpPairManagerCounts(manager *flowPairManager, sessionID wire.SessionID) (records, pending, sessionPending int) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return len(manager.udpRecords), manager.udpWaiting, manager.perSession[sessionID]
}

func waitForTCPPending(t *testing.T, manager *flowPairManager, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		manager.mu.Lock()
		got := len(manager.pending)
		manager.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("TCP pending count = %d, want %d", got, want)
		}
		runtime.Gosched()
	}
}

func TestUDPPairCancelWaitingReleasesRecordAndCounters(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	sessionID := wire.SessionID{1}
	open, _ := udpPairHeaders(1)
	uplink := newUDPPairTestUplink()
	handle, paired, err := manager.SubmitUDP(context.Background(), sessionID, open, "waiting.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink})
	if err != nil || handle == nil || paired != nil {
		t.Fatalf("SubmitUDP = (%v, %v, %v)", handle, paired, err)
	}
	if records, pending, sessionPending := udpPairManagerCounts(manager, sessionID); records != 1 || pending != 1 || sessionPending != 1 {
		t.Fatalf("before cancel records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}

	cause := errors.New("cancel waiting")
	manager.cancelUDP(sessionID, open.FlowID, cause)

	if records, pending, sessionPending := udpPairManagerCounts(manager, sessionID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("after cancel records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
	if uplink.closeCount.Load() != 1 {
		t.Fatalf("uplink close count = %d, want 1", uplink.closeCount.Load())
	}
	if !errors.Is(handle.Err(), cause) {
		t.Fatalf("handle error = %v, want %v", handle.Err(), cause)
	}
}

func TestUDPPairCancelWaitingDrainsQueuedBytes(t *testing.T) {
	routes := make(chan packetRoute, 1)
	session, _ := newUDPTestSession(t, Limits{QUICQueuePackets: 4, QUICQueueBytes: 64}, routes)
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	open, _ := udpPairHeaders(2)
	uplink := newQUICUDPUplink(session)
	uplink.Deliver([]byte("queued"))
	if got := sessionQueuedBytes(session); got != len("queued") {
		t.Fatalf("queued bytes before submit = %d, want %d", got, len("queued"))
	}
	if _, _, err := manager.SubmitUDP(context.Background(), session.ID, open, "queue.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink}); err != nil {
		t.Fatal(err)
	}

	manager.cancelUDP(session.ID, open.FlowID, net.ErrClosed)

	if got := sessionQueuedBytes(session); got != 0 {
		t.Fatalf("queued bytes after cancel = %d, want 0", got)
	}
}

func TestUDPPairCancelWaitingWakesWaiter(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	sessionID := wire.SessionID{3}
	open, _ := udpPairHeaders(3)
	handle, _, err := manager.SubmitUDP(context.Background(), sessionID, open, "wake.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: newUDPPairTestUplink()})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	woke := make(chan struct{})
	go func() {
		close(started)
		<-handle.Done()
		close(woke)
	}()
	<-started

	manager.cancelUDP(sessionID, open.FlowID, context.Canceled)

	select {
	case <-woke:
	case <-time.After(time.Second):
		t.Fatal("waiting handle was not woken by cancellation")
	}
}

func TestUDPPairCancelBeforeBindClosesCompletedPair(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	sessionID := wire.SessionID{4}
	handle, paired, uplink, downlink := completeUDPPair(t, manager, sessionID, 4)
	conn := newPairedUDPConn(paired)
	conn.setFinish(func(err error) { manager.finishUDP(handle, err) })

	manager.cancelUDP(sessionID, paired.FlowID, context.Canceled)
	if manager.bindUDP(handle, conn) {
		t.Fatal("bindUDP activated a canceled completed pair")
	}

	if uplink.closeCount.Load() != 1 || downlink.closeCount.Load() != 1 {
		t.Fatalf("close counts uplink=%d downlink=%d, want 1/1", uplink.closeCount.Load(), downlink.closeCount.Load())
	}
	if records, _, _ := udpPairManagerCounts(manager, sessionID); records != 0 {
		t.Fatalf("records after canceled bind = %d, want 0", records)
	}
}

func TestUDPPairCancelActiveInterruptsBlockedRead(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	sessionID := wire.SessionID{5}
	handle, paired, uplink, _ := completeUDPPair(t, manager, sessionID, 5)
	conn := bindUDPPair(t, manager, handle, paired)
	readDone := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadFrom(make([]byte, 8))
		readDone <- err
	}()
	<-uplink.readStarted

	manager.cancelUDP(sessionID, paired.FlowID, net.ErrClosed)

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("blocked read returned nil after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("active cancellation did not interrupt blocked read")
	}
}

func TestUDPPairCancelActiveClosesOppositeHalf(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	sessionID := wire.SessionID{6}
	handle, paired, _, downlink := completeUDPPair(t, manager, sessionID, 6)
	_ = bindUDPPair(t, manager, handle, paired)

	manager.cancelUDP(sessionID, paired.FlowID, io.EOF)

	select {
	case <-downlink.closed:
	case <-time.After(time.Second):
		t.Fatal("active cancellation did not close the downlink half")
	}
	if downlink.closeCount.Load() != 1 {
		t.Fatalf("downlink close count = %d, want 1", downlink.closeCount.Load())
	}
}

func TestUDPPairCancelActiveInterruptsBlockedTCPDownlinkWrite(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	sessionID := wire.SessionID{25}
	open, attach := udpPairHeaders(28)
	uplink := newUDPPairTestUplink()
	handle, _, err := manager.SubmitUDP(context.Background(), sessionID, open, "blocked-write.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink})
	if err != nil {
		t.Fatal(err)
	}
	physical := newBlockingUDPWriteConn()
	defer physical.forceRelease()
	_, paired, err := manager.SubmitUDP(context.Background(), sessionID, attach, "blocked-write.example:53", udpHalf{Role: wire.FlowRoleAttach, Downlink: newTCPUDPDownlink(physical)})
	if err != nil || paired == nil {
		t.Fatalf("SubmitUDP(attach) = (%v, %v)", paired, err)
	}
	conn := bindUDPPair(t, manager, handle, paired)
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("blocked"), nil)
		writeDone <- err
	}()
	select {
	case <-physical.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("TCP downlink write did not reach the blocking connection")
	}

	cancelDone := make(chan struct{})
	go func() {
		manager.cancelUDP(sessionID, paired.FlowID, net.ErrClosed)
		close(cancelDone)
	}()
	select {
	case <-cancelDone:
	case <-time.After(250 * time.Millisecond):
		physical.forceRelease()
		<-cancelDone
		<-writeDone
		t.Fatal("active cancellation waited for the blocked TCP downlink write")
	}

	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("blocked WriteTo returned nil after physical close")
		}
	case <-time.After(time.Second):
		t.Fatal("physical close did not release the blocked WriteTo")
	}
	if uplink.closeCount.Load() != 1 || physical.closeCount.Load() != 1 {
		t.Fatalf("physical close counts uplink=%d downlink=%d, want 1/1", uplink.closeCount.Load(), physical.closeCount.Load())
	}
}

func TestUDPPairCancelActiveTCPWriteCloseCannotDelayPhysicalClose(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	sessionID := wire.SessionID{26}
	open, attach := udpPairHeaders(29)
	uplink := newUDPPairTestUplink()
	handle, _, err := manager.SubmitUDP(context.Background(), sessionID, open, "blocked-close.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink})
	if err != nil {
		t.Fatal(err)
	}
	physical := newBlockingUDPWriteConn()
	defer physical.forceRelease()
	_, paired, err := manager.SubmitUDP(context.Background(), sessionID, attach, "blocked-close.example:53", udpHalf{Role: wire.FlowRoleAttach, Downlink: newTCPUDPDownlink(physical)})
	if err != nil || paired == nil {
		t.Fatalf("SubmitUDP(attach) = (%v, %v)", paired, err)
	}
	_ = bindUDPPair(t, manager, handle, paired)

	cancelDone := make(chan struct{})
	go func() {
		manager.cancelUDP(sessionID, paired.FlowID, net.ErrClosed)
		close(cancelDone)
	}()
	select {
	case <-cancelDone:
	case <-time.After(250 * time.Millisecond):
		physical.forceRelease()
		<-cancelDone
		t.Fatal("TCP WriteClose delayed physical downlink close")
	}

	if uplink.closeCount.Load() != 1 || physical.closeCount.Load() != 1 {
		t.Fatalf("physical close counts uplink=%d downlink=%d, want 1/1", uplink.closeCount.Load(), physical.closeCount.Load())
	}
}

func TestUDPPairSessionCancelClosesWaitingAndActive(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	sessionID := wire.SessionID{7}
	open, _ := udpPairHeaders(7)
	waitingUplink := newUDPPairTestUplink()
	waitingHandle, _, err := manager.SubmitUDP(context.Background(), sessionID, open, "waiting.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: waitingUplink})
	if err != nil {
		t.Fatal(err)
	}
	activeHandle, activePair, activeUplink, activeDownlink := completeUDPPair(t, manager, sessionID, 8)
	_ = bindUDPPair(t, manager, activeHandle, activePair)

	manager.cancelUDPSession(sessionID, net.ErrClosed)

	if waitingUplink.closeCount.Load() != 1 || activeUplink.closeCount.Load() != 1 || activeDownlink.closeCount.Load() != 1 {
		t.Fatalf("close counts waiting=%d active_up=%d active_down=%d", waitingUplink.closeCount.Load(), activeUplink.closeCount.Load(), activeDownlink.closeCount.Load())
	}
	select {
	case <-waitingHandle.Done():
	default:
		t.Fatal("waiting handle was not closed by session cancellation")
	}
	if records, pending, sessionPending := udpPairManagerCounts(manager, sessionID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("after session cancel records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
}

func TestUDPPairRouteCompletionRemovesRecordOnce(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	sessionID := wire.SessionID{8}
	handle, paired, uplink, downlink := completeUDPPair(t, manager, sessionID, 9)
	_ = bindUDPPair(t, manager, handle, paired)
	cause := errors.New("route complete")

	manager.finishUDP(handle, cause)
	manager.finishUDP(handle, errors.New("late finish"))

	if records, pending, sessionPending := udpPairManagerCounts(manager, sessionID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("after finish records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
	if uplink.closeCount.Load() != 1 || downlink.closeCount.Load() != 1 {
		t.Fatalf("close counts uplink=%d downlink=%d, want 1/1", uplink.closeCount.Load(), downlink.closeCount.Load())
	}
	if !errors.Is(handle.Err(), cause) {
		t.Fatalf("handle error = %v, want first cause %v", handle.Err(), cause)
	}
}

func TestUDPPairTimeoutUsesSameFinishPath(t *testing.T) {
	manager := newFlowPairManager(20 * time.Millisecond)
	defer manager.Close()
	sessionID := wire.SessionID{9}
	open, _ := udpPairHeaders(10)
	uplink := newUDPPairTestUplink()
	handle, _, err := manager.SubmitUDP(context.Background(), sessionID, open, "timeout.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-handle.Done():
	case <-time.After(time.Second):
		t.Fatal("UDP pair timeout did not finish the record")
	}

	if !errors.Is(handle.Err(), ErrPairTimeout) {
		t.Fatalf("handle error = %v, want ErrPairTimeout", handle.Err())
	}
	select {
	case <-uplink.closed:
	case <-time.After(time.Second):
		t.Fatal("timeout did not close the stored uplink")
	}
	if uplink.closeCount.Load() != 1 {
		t.Fatalf("uplink close count = %d, want 1", uplink.closeCount.Load())
	}
	if records, pending, sessionPending := udpPairManagerCounts(manager, sessionID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("after timeout records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
}

func TestUDPPairMetadataConflictClosesBothHalves(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	defer manager.Close()
	sessionID := wire.SessionID{10}
	open, attach := udpPairHeaders(11)
	uplink := newUDPPairTestUplink()
	handle, _, err := manager.SubmitUDP(context.Background(), sessionID, open, "first.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink})
	if err != nil {
		t.Fatal(err)
	}
	downlink := newUDPPairTestDownlink()
	_, _, err = manager.SubmitUDP(context.Background(), sessionID, attach, "second.example:53", udpHalf{Role: wire.FlowRoleAttach, Downlink: downlink})
	if !errors.Is(err, ErrCarrierMismatch) {
		t.Fatalf("metadata conflict = %v, want ErrCarrierMismatch", err)
	}

	if uplink.closeCount.Load() != 1 {
		t.Fatalf("manager-owned uplink close count = %d, want 1", uplink.closeCount.Load())
	}
	if downlink.closeCount.Load() != 0 {
		t.Fatalf("arriving downlink close count after Submit error = %d, want caller ownership", downlink.closeCount.Load())
	}
	closeUDPHalfWithError(udpHalf{Role: wire.FlowRoleAttach, Downlink: downlink}, err)
	if downlink.closeCount.Load() != 1 {
		t.Fatalf("arriving downlink close count after caller cleanup = %d, want 1", downlink.closeCount.Load())
	}
	if !errors.Is(handle.Err(), ErrCarrierMismatch) {
		t.Fatalf("waiting handle error = %v, want ErrCarrierMismatch", handle.Err())
	}
	if records, pending, sessionPending := udpPairManagerCounts(manager, sessionID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("after conflict records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
}

func TestUDPPairPendingLimitRemainsSharedWithTCP(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	manager.configureLimits(Limits{PendingPairsPerSession: 1, PendingPairsGlobal: 1})
	defer manager.Close()

	udpSession := wire.SessionID{11}
	openUDP, _ := udpPairHeaders(12)
	if _, _, err := manager.SubmitUDP(context.Background(), udpSession, openUDP, "udp.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: newUDPPairTestUplink()}); err != nil {
		t.Fatal(err)
	}
	tcpHeader := wire.FlowHeader{Role: wire.FlowRoleOpen, FlowID: 13, Kind: wire.FlowKindTCP, Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP}
	tcpConn, tcpPeer := net.Pipe()
	defer tcpPeer.Close()
	if _, err := manager.SubmitTCP(context.Background(), wire.SessionID{12}, tcpHeader, "tcp.example:443", tcpConn); !errors.Is(err, ErrPairLimit) {
		t.Fatalf("TCP behind UDP pending = %v, want ErrPairLimit", err)
	}
	_ = tcpConn.Close()
	manager.cancelUDP(udpSession, openUDP.FlowID, net.ErrClosed)

	tcpCtx, cancelTCP := context.WithCancel(context.Background())
	defer cancelTCP()
	tcpConn, tcpPeer2 := net.Pipe()
	defer tcpPeer2.Close()
	tcpDone := make(chan error, 1)
	go func() {
		_, err := manager.SubmitTCP(tcpCtx, wire.SessionID{13}, tcpHeader, "tcp.example:443", tcpConn)
		tcpDone <- err
	}()
	waitForTCPPending(t, manager, 1)
	openUDP.FlowID = 14
	rejected := newUDPPairTestUplink()
	if _, _, err := manager.SubmitUDP(context.Background(), wire.SessionID{14}, openUDP, "udp.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: rejected}); !errors.Is(err, ErrPairLimit) {
		t.Fatalf("UDP behind TCP pending = %v, want ErrPairLimit", err)
	}
	_ = rejected.Close()
	cancelTCP()
	select {
	case err := <-tcpDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("TCP waiter error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP waiter did not stop")
	}

	manager.configureLimits(Limits{PendingPairsPerSession: 1, PendingPairsGlobal: 2})
	sharedSession := wire.SessionID{15}
	openUDP.FlowID = 15
	if _, _, err := manager.SubmitUDP(context.Background(), sharedSession, openUDP, "udp.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: newUDPPairTestUplink()}); err != nil {
		t.Fatal(err)
	}
	tcpHeader.FlowID = 16
	tcpConn, tcpPeer3 := net.Pipe()
	defer tcpPeer3.Close()
	if _, err := manager.SubmitTCP(context.Background(), sharedSession, tcpHeader, "tcp.example:443", tcpConn); !errors.Is(err, ErrPairLimit) {
		t.Fatalf("TCP exceeded per-session limit held by UDP = %v, want ErrPairLimit", err)
	}
	_ = tcpConn.Close()
	manager.cancelUDP(sharedSession, openUDP.FlowID, net.ErrClosed)
}

func TestUDPPairUpstreamSuccessRetainsOwnership(t *testing.T) {
	owned := make(chan net.PacketConn, 1)
	config, err := NewConfig(ConfigOptions{Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{
		Config: config,
		Upstream: upstreamFuncs{packet: func(_ context.Context, conn net.PacketConn, _ net.Addr, _ string) error {
			owned <- conn
			return nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	sessionID := wire.SessionID{21}
	open, attach := udpPairHeaders(21)
	uplink := newUDPPairTestUplink()
	downlink := newUDPPairTestDownlink()
	if err := handler.submitAndRouteUDP(context.Background(), nil, sessionID, open, "owned.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink}); err != nil {
		t.Fatal(err)
	}
	if err := handler.submitAndRouteUDP(context.Background(), nil, sessionID, attach, "owned.example:53", udpHalf{Role: wire.FlowRoleAttach, Downlink: downlink}); err != nil {
		t.Fatal(err)
	}

	var conn net.PacketConn
	select {
	case conn = <-owned:
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive the paired packet conn")
	}
	if records, pending, _ := udpPairManagerCounts(handler.pairing, sessionID); records != 1 || pending != 0 {
		t.Fatalf("after successful handoff records=%d pending=%d, want active record", records, pending)
	}
	uplink.Deliver([]byte("after-return"))
	buffer := make([]byte, 64)
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("ReadFrom after successful HandlePacket return: %v", err)
	}
	if got := string(buffer[:n]); got != "after-return" {
		t.Fatalf("payload after successful HandlePacket return = %q", got)
	}
	if n, err := conn.WriteTo([]byte("response"), nil); err != nil || n != len("response") {
		t.Fatalf("WriteTo after successful HandlePacket return = (%d, %v)", n, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if records, _, _ := udpPairManagerCounts(handler.pairing, sessionID); records != 0 {
		t.Fatalf("records after upstream close = %d, want 0", records)
	}
}

func TestUDPPairOwnedTCPCloseHandlerCanReenterHandlerClose(t *testing.T) {
	config, err := NewConfig(ConfigOptions{Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}})
	if err != nil {
		t.Fatal(err)
	}

	left, right := net.Pipe()
	defer right.Close()
	sessionID := wire.SessionID{22}
	callbackDone := make(chan struct{})
	var callbackSawRecord atomic.Bool
	life := newLifecycle(context.Background(), left, func(error) {
		if records, _, _ := udpPairManagerCounts(handler.pairing, sessionID); records != 0 {
			callbackSawRecord.Store(true)
		}
		_ = handler.Close()
		close(callbackDone)
	}, nil)
	owned := &ownedConn{Conn: left, life: life}
	open := wire.FlowHeader{Role: wire.FlowRoleOpen, FlowID: 22, Kind: wire.FlowKindUDP, Uplink: wire.CarrierTCP, Downlink: wire.CarrierUDP}
	attach := open
	attach.Role = wire.FlowRoleAttach
	handle, paired, err := handler.pairing.SubmitUDP(context.Background(), sessionID, open, "reenter.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: newTCPUDPUplink(owned)})
	if err != nil || paired != nil {
		t.Fatalf("SubmitUDP(open) = (%v, %v)", paired, err)
	}
	downlink := newUDPPairTestDownlink()
	_, paired, err = handler.pairing.SubmitUDP(context.Background(), sessionID, attach, "reenter.example:53", udpHalf{Role: wire.FlowRoleAttach, Downlink: downlink})
	if err != nil || paired == nil {
		t.Fatalf("SubmitUDP(attach) = (%v, %v)", paired, err)
	}
	conn := bindUDPPair(t, handler.pairing, handle, paired)
	closeDone := make(chan struct{})
	go func() {
		_ = conn.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("owned TCP CloseHandler reentry deadlocked paired UDP close")
	}
	select {
	case <-callbackDone:
	case <-time.After(time.Second):
		t.Fatal("owned TCP CloseHandler did not complete")
	}
	if callbackSawRecord.Load() {
		t.Fatal("owned TCP CloseHandler observed the active record during physical close")
	}
	if records, _, _ := udpPairManagerCounts(handler.pairing, sessionID); records != 0 {
		t.Fatalf("records after reentrant close = %d, want 0", records)
	}
	if downlink.closeCount.Load() != 1 {
		t.Fatalf("downlink close count = %d, want 1", downlink.closeCount.Load())
	}
}

func TestUDPPairPortalSessionCloseCancelsAllManagerPhases(t *testing.T) {
	config, err := NewConfig(ConfigOptions{Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerOptions{Config: config, Upstream: noopUpstream{}})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	sessionID := wire.SessionID{23}
	session := newPortalSession(sessionID, &fakeQuicConn{}, handler, nil)

	waitingOpen, _ := udpPairHeaders(23)
	waitingUplink := newUDPPairTestUplink()
	if _, _, err := handler.pairing.SubmitUDP(context.Background(), sessionID, waitingOpen, "waiting.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: waitingUplink}); err != nil {
		t.Fatal(err)
	}
	_, _, pairedUplink, pairedDownlink := completeUDPPair(t, handler.pairing, sessionID, 24)
	activeHandle, activePair, activeUplink, activeDownlink := completeUDPPair(t, handler.pairing, sessionID, 25)
	_ = bindUDPPair(t, handler.pairing, activeHandle, activePair)

	session.Close()

	if records, pending, sessionPending := udpPairManagerCounts(handler.pairing, sessionID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("after session close records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
	if waitingUplink.closeCount.Load() != 1 || pairedUplink.closeCount.Load() != 1 || pairedDownlink.closeCount.Load() != 1 || activeUplink.closeCount.Load() != 1 || activeDownlink.closeCount.Load() != 1 {
		t.Fatalf("session close counts waiting=%d paired=%d/%d active=%d/%d", waitingUplink.closeCount.Load(), pairedUplink.closeCount.Load(), pairedDownlink.closeCount.Load(), activeUplink.closeCount.Load(), activeDownlink.closeCount.Load())
	}
}

func TestUDPPairManagerCloseRacesExternalClose(t *testing.T) {
	manager := newFlowPairManager(time.Second)
	sessionID := wire.SessionID{24}
	handle, paired, uplink, downlink := completeUDPPair(t, manager, sessionID, 26)
	conn := bindUDPPair(t, manager, handle, paired)
	start := make(chan struct{})
	managerDone := make(chan struct{})
	externalDone := make(chan struct{})
	go func() {
		<-start
		manager.Close()
		close(managerDone)
	}()
	go func() {
		<-start
		_ = conn.Close()
		close(externalDone)
	}()
	close(start)

	for name, done := range map[string]<-chan struct{}{"manager Close": managerDone, "external Close": externalDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s did not return", name)
		}
	}
	if records, pending, sessionPending := udpPairManagerCounts(manager, sessionID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Fatalf("after concurrent close records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
	if uplink.closeCount.Load() != 1 || downlink.closeCount.Load() != 1 {
		t.Fatalf("concurrent close counts uplink=%d downlink=%d, want 1/1", uplink.closeCount.Load(), downlink.closeCount.Load())
	}
}

func TestUDPPairPortalSessionCloseRejectsInFlightCanceledSubmit(t *testing.T) {
	routes := make(chan packetRoute, 1)
	session, _ := newUDPTestSession(t, Limits{QUICQueuePackets: 4, QUICQueueBytes: 64}, routes)
	ctx, cancel := context.WithCancel(context.Background())
	cancelCalled := make(chan struct{})
	session.cancel = func() {
		cancel()
		close(cancelCalled)
	}
	open, _ := udpPairHeaders(27)
	uplink := newQUICUDPUplink(session)
	uplink.Deliver([]byte("in-flight"))
	if got := sessionQueuedBytes(session); got != len("in-flight") {
		t.Fatalf("queued bytes before close = %d, want %d", got, len("in-flight"))
	}

	session.Handler.pairing.mu.Lock()
	submitStarted := make(chan struct{})
	submitDone := make(chan error, 1)
	go func() {
		close(submitStarted)
		submitDone <- session.Handler.submitAndRouteUDP(ctx, session.Source, session.ID, open, "in-flight.example:53", udpHalf{Role: wire.FlowRoleOpen, Uplink: uplink})
	}()
	<-submitStarted

	closeStarted := make(chan struct{})
	closeDone := make(chan struct{})
	go func() {
		close(closeStarted)
		session.Close()
		close(closeDone)
	}()
	<-closeStarted

	canceledBeforeRelease := false
	select {
	case <-cancelCalled:
		canceledBeforeRelease = true
	case <-time.After(100 * time.Millisecond):
	}
	session.Handler.pairing.mu.Unlock()

	var submitErr error
	select {
	case submitErr = <-submitDone:
	case <-time.After(time.Second):
		t.Fatal("in-flight UDP submit did not return")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("portalSession.Close did not return")
	}

	if !canceledBeforeRelease {
		t.Error("portalSession.Close did not cancel the session before waiting on pairing cleanup")
	}
	if !errors.Is(submitErr, context.Canceled) {
		t.Errorf("in-flight submit error = %v, want context.Canceled", submitErr)
	}
	if records, pending, sessionPending := udpPairManagerCounts(session.Handler.pairing, session.ID); records != 0 || pending != 0 || sessionPending != 0 {
		t.Errorf("after close records=%d pending=%d session_pending=%d", records, pending, sessionPending)
	}
	if got := sessionQueuedBytes(session); got != 0 {
		t.Errorf("queued bytes after close = %d, want 0", got)
	}
	select {
	case <-uplink.closed:
	default:
		t.Error("rejected in-flight uplink was not closed")
	}
}

func sessionQueuedBytes(session *portalSession) int {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.queuedBytes
}
