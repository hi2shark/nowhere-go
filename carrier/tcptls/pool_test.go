package tcptls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hi2shark/nowhere-go/wire"
)

type capturingLogger struct {
	ch chan string
}

func newCapturingLogger() *capturingLogger {
	return &capturingLogger{ch: make(chan string, 256)}
}

func (l *capturingLogger) Debugf(format string, args ...any) {
	select {
	case l.ch <- fmt.Sprintf(format, args...):
	default:
	}
}

func (l *capturingLogger) Warnf(format string, args ...any) {
	l.Debugf(format, args...)
}

func TestTCPPoolWarmBorrowConsumesCarrier(t *testing.T) {
	dialer := &recordingTCPDialer{}
	pool := NewTCPPool(testTCPConfig(t, dialer), 1)
	defer pool.Close()

	pool.prepareOne()
	waitPoolIdle(t, pool, 1)
	warm := dialer.connAt(0)

	conn, err := pool.Acquire(context.Background(), "example.com:443", TCPRelayTCP)
	if err != nil {
		t.Fatalf("Acquire warm: %v", err)
	}
	if got := trackedRecordingConn(t, conn); got != warm {
		t.Fatalf("Acquire returned conn %p, want warm conn %p", got, warm)
	}
	_ = conn.Close()

	waitPoolIdle(t, pool, 1)
	pool.mu.Lock()
	idle := append([]*warmConn(nil), pool.idle...)
	pool.mu.Unlock()
	for _, wc := range idle {
		if wc.conn == warm {
			t.Fatalf("consumed warm carrier returned to idle pool")
		}
	}
	if !warm.closed() {
		t.Fatalf("consumed warm carrier was not closed after relay Close")
	}
}

func TestTCPPoolFallsBackFreshWhenWarmActivationFails(t *testing.T) {
	failingWarm := newRecordingNetConn("warm")
	failingWarm.failWriteAt = 2 // auth write succeeds during prepare; request write fails during activation.
	dialer := &recordingTCPDialer{queued: []*recordingNetConn{failingWarm}}
	pool := NewTCPPool(testTCPConfig(t, dialer), 1)
	defer pool.Close()

	pool.prepareOne()
	waitPoolIdle(t, pool, 1)

	conn, err := pool.Acquire(context.Background(), "example.com:443", TCPRelayTCP)
	if err != nil {
		t.Fatalf("Acquire fallback: %v", err)
	}
	defer conn.Close()
	if got := trackedRecordingConn(t, conn); got == failingWarm {
		t.Fatalf("Acquire returned the failed warm carrier")
	}
	if !failingWarm.closed() {
		t.Fatalf("failed warm carrier was not closed")
	}
	waitPoolIdle(t, pool, 1)
	pool.mu.Lock()
	idle := len(pool.idle)
	preparing := pool.preparing
	target := pool.target
	pool.mu.Unlock()
	if idle+preparing > target {
		t.Fatalf("pool overfilled after warm fallback: idle=%d preparing=%d target=%d", idle, preparing, target)
	}
}

func TestTCPPoolConcurrentAcquireUsesDistinctWarmCarriers(t *testing.T) {
	const n = 6
	dialer := &recordingTCPDialer{}
	pool := NewTCPPool(testTCPConfig(t, dialer), n)
	defer pool.Close()
	for i := 0; i < n; i++ {
		pool.prepareOne()
	}
	waitPoolIdle(t, pool, n)

	start := make(chan struct{})
	results := make(chan net.Conn, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			conn, err := pool.Acquire(context.Background(), "example.com:443", TCPRelayTCP)
			if err != nil {
				errs <- err
				return
			}
			results <- conn
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("Acquire: %v", err)
	}

	seen := make(map[*recordingNetConn]bool, n)
	for conn := range results {
		inner := trackedRecordingConn(t, conn)
		if seen[inner] {
			t.Fatalf("carrier %p was handed to more than one concurrent Acquire", inner)
		}
		seen[inner] = true
		_ = conn.Close()
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct carriers, want %d", len(seen), n)
	}
}

func TestTCPPoolEvictDoesNotCloseBorrowedCarrier(t *testing.T) {
	dialer := &recordingTCPDialer{}
	pool := NewTCPPool(testTCPConfig(t, dialer), 1)
	defer pool.Close()

	pool.prepareOne()
	waitPoolIdle(t, pool, 1)

	pool.mu.Lock()
	wc := pool.idle[0]
	pool.idle = nil
	pool.mu.Unlock()

	pool.evict(wc)
	if wc.conn.(*recordingNetConn).closed() {
		t.Fatalf("evict closed a carrier that had already left the idle pool")
	}
	_ = wc.conn.Close()
}

func TestTCPPoolZeroTargetConcurrentAcquireUsesParallelFreshDials(t *testing.T) {
	const n = 6
	dialer := newParallelDialer(n)
	pool := NewTCPPool(testTCPConfig(t, dialer), 0)
	defer pool.Close()

	start := make(chan struct{})
	results := make(chan net.Conn, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			conn, err := pool.Acquire(context.Background(), "example.com:443", TCPRelayTCP)
			if err != nil {
				errs <- err
				return
			}
			results <- conn
		}()
	}
	close(start)

	select {
	case <-dialer.allStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("fresh dials did not run in parallel; started=%d want=%d", dialer.startedCount(), n)
	}
	close(dialer.release)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("Acquire: %v", err)
	}
	for conn := range results {
		_ = conn.Close()
	}
	if got := dialer.maxActiveCount(); got < n {
		t.Fatalf("max concurrent fresh dials = %d, want at least %d", got, n)
	}
	waitPoolIdle(t, pool, 0)
}

func TestTCPPoolEmptyPoolAcquireDoesNotWaitForBlockedWarmPrepare(t *testing.T) {
	dialer := newBlockingPrepareDialer()
	pool := NewTCPPool(testTCPConfig(t, dialer), 1)
	defer pool.Close()

	ctx := context.WithValue(context.Background(), freshDialContextKey{}, true)
	done := make(chan error, 1)
	go func() {
		conn, err := pool.Acquire(ctx, "example.com:443", TCPRelayTCP)
		if err == nil {
			_ = conn.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Acquire: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Acquire waited for blocked background warm prepare")
	}

	select {
	case <-dialer.warmStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("background warm prepare was not started after cold miss")
	}
	close(dialer.releaseWarm)
	waitPoolIdle(t, pool, 1)
}

func TestTCPPoolCloseDropsWarmPreparedAfterClose(t *testing.T) {
	dialer := newBlockingPrepareDialer()
	pool := NewTCPPool(testTCPConfig(t, dialer), 1)

	done := make(chan struct{})
	go func() {
		pool.prepareOne()
		close(done)
	}()

	select {
	case <-dialer.warmStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("warm prepare did not start")
	}
	pool.Close()
	close(dialer.releaseWarm)

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("prepareOne did not finish after Close")
	}
	waitPoolIdle(t, pool, 0)
	for _, conn := range dialer.snapshot() {
		if !conn.closed() {
			t.Fatalf("Close left prepared carrier %s open", conn.name)
		}
	}
}

func TestTCPPoolAcquireLogsOutcomeAndPoolSnapshot(t *testing.T) {
	logger := newCapturingLogger()
	sub := logger.ch

	dialer := &recordingTCPDialer{}
	pool := NewTCPPool(testTCPConfig(t, dialer, logger), 0)
	defer pool.Close()

	conn, err := pool.Acquire(context.Background(), "example.com:443", TCPRelayTCP)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	_ = conn.Close()

	payload := waitForLogPayload(t, sub, "pool_acquire")
	for _, want := range []string{
		"outcome=fresh",
		"flow_id=",
		"carrier_id=",
		"idle=",
		"preparing=",
		"target=",
		"elapsed_ms=",
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("pool_acquire log %q missing %q", payload, want)
		}
	}
}

func TestTCPPoolOpenTimingLogsFreshWarmAndFallbackPaths(t *testing.T) {
	logger := newCapturingLogger()
	sub := logger.ch

	freshPool := NewTCPPool(testTCPConfig(t, &recordingTCPDialer{}, logger), 0)
	defer freshPool.Close()
	freshConn, err := freshPool.Acquire(context.Background(), "example.com:443", TCPRelayTCP)
	if err != nil {
		t.Fatalf("Acquire fresh: %v", err)
	}
	_ = freshConn.Close()

	payload := waitForLogPayloads(t, sub, "open_timing", "outcome=fresh", "stage=fresh_tls")
	assertOpenTimingFields(t, payload, "network=tcp", "target=example.com:443")

	warmDialer := &recordingTCPDialer{}
	warmPool := NewTCPPool(testTCPConfig(t, warmDialer, logger), 1)
	defer warmPool.Close()
	warmPool.prepareOne()
	waitPoolIdle(t, warmPool, 1)

	preparePayload := waitForLogPayloads(t, sub, "open_timing", "outcome=warm_prepare", "stage=tls")
	assertOpenTimingFields(t, preparePayload, "network=tcp", "target=127.0.0.1:1")

	warmConn, err := warmPool.Acquire(context.Background(), "example.com:443", TCPRelayTCP)
	if err != nil {
		t.Fatalf("Acquire warm: %v", err)
	}
	_ = warmConn.Close()

	warmPayload := waitForLogPayloads(t, sub, "open_timing", "outcome=warm", "stage=warm_activate")
	assertOpenTimingFields(t, warmPayload, "network=tcp", "target=example.com:443")

	failingWarm := newRecordingNetConn("warm")
	failingWarm.failWriteAt = 2
	fallbackDialer := &recordingTCPDialer{queued: []*recordingNetConn{failingWarm}}
	fallbackPool := NewTCPPool(testTCPConfig(t, fallbackDialer, logger), 1)
	defer fallbackPool.Close()
	fallbackPool.prepareOne()
	waitPoolIdle(t, fallbackPool, 1)
	_ = waitForLogPayloads(t, sub, "open_timing", "outcome=warm_prepare", "stage=tls")

	fallbackConn, err := fallbackPool.Acquire(context.Background(), "example.com:443", TCPRelayTCP)
	if err != nil {
		t.Fatalf("Acquire fallback: %v", err)
	}
	_ = fallbackConn.Close()

	failedWarmPayload := waitForLogPayloads(t, sub, "open_timing", "outcome=warm_failed", "stage=warm_activate")
	assertOpenTimingFields(t, failedWarmPayload, "network=tcp", "target=example.com:443")
	fallbackPayload := waitForLogPayloads(t, sub, "open_timing", "outcome=warm_failed_fresh", "stage=fresh_tls")
	assertOpenTimingFields(t, fallbackPayload, "network=tcp", "target=example.com:443")
}

func TestTCPPoolOpenTimingLogsAsymmetricLanes(t *testing.T) {
	logger := newCapturingLogger()
	sub := logger.ch

	pool := NewTCPPool(testTCPConfig(t, &recordingTCPDialer{}, logger), 0)
	defer pool.Close()

	header := wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		FlowID:   42,
		Kind:     wire.FlowKindTCP,
		Uplink:   wire.CarrierTCP,
		Downlink: wire.CarrierUDP,
	}
	flowConn, err := pool.AcquireFlowHalf(context.Background(), "example.com:443", header)
	if err != nil {
		t.Fatalf("AcquireFlowHalf: %v", err)
	}
	_ = flowConn.Close()

	tcpPayload := waitForLogPayloads(t, sub, "open_timing", "outcome=fresh", "stage=flow_lane")
	assertOpenTimingFields(t, tcpPayload, "network=tcp", "target=example.com:443", "flow_id=42")

	uotHeader := wire.FlowHeader{
		Role:     wire.FlowRoleAttach,
		FlowID:   43,
		Kind:     wire.FlowKindUDP,
		Uplink:   wire.CarrierUDP,
		Downlink: wire.CarrierTCP,
	}
	uotConn, err := pool.AcquireUDPFlowHalf(context.Background(), "example.com:443", uotHeader)
	if err != nil {
		t.Fatalf("AcquireUDPFlowHalf: %v", err)
	}
	_ = uotConn.Close()

	udpPayload := waitForLogPayloads(t, sub, "open_timing", "outcome=fresh", "stage=udp_flow_lane")
	assertOpenTimingFields(t, udpPayload, "network=udp", "target=example.com:443", "flow_id=43")
}

func TestTuneNowhereTCPConnIsBestEffort(t *testing.T) {
	setSocketBufferEnv(t, nil)

	plain := newRecordingNetConn("plain")
	tuneNowhereTCPConn(nil, plain, 1, "plain")
	if plain.closed() {
		t.Fatalf("best-effort tuning closed a plain net.Conn")
	}

	tunable := &recordingTunableConn{recordingNetConn: newRecordingNetConn("tunable")}
	tuneNowhereTCPConn(nil, tunable, 2, "tunable")
	if !tunable.noDelay || !tunable.keepAlive {
		t.Fatalf("tuning did not enable noDelay/keepAlive: noDelay=%v keepAlive=%v", tunable.noDelay, tunable.keepAlive)
	}
	if tunable.keepAlivePeriod == 0 {
		t.Fatalf("tuning did not set keepalive period")
	}
	if tunable.readBufferCalls != 0 || tunable.writeBufferCalls != 0 {
		t.Fatalf("default tuning forced socket buffers: read_calls=%d write_calls=%d", tunable.readBufferCalls, tunable.writeBufferCalls)
	}

	failing := &recordingTunableConn{
		recordingNetConn: newRecordingNetConn("failing"),
		err:              errors.New("unsupported"),
	}
	tuneNowhereTCPConn(nil, failing, 3, "failing")
	if failing.closed() {
		t.Fatalf("best-effort tuning closed a conn after setter errors")
	}
	if failing.noDelayCalls == 0 || failing.keepAliveCalls == 0 {
		t.Fatalf("tuning did not attempt all setters after errors: %+v", failing)
	}
	if failing.readBufferCalls != 0 || failing.writeBufferCalls != 0 {
		t.Fatalf("default tuning forced socket buffers after setter errors: %+v", failing)
	}
}

func TestTuneNowhereTCPConnSocketBufferEnv(t *testing.T) {
	t.Run("unset keeps autotuning and logs forced false", func(t *testing.T) {
		setSocketBufferEnv(t, nil)
		logger := newCapturingLogger()
		sub := logger.ch

		tunable := &recordingTunableConn{recordingNetConn: newRecordingNetConn("default")}
		tuneNowhereTCPConn(&Config{logger: logger}, tunable, 10, "default")

		if tunable.readBufferCalls != 0 || tunable.writeBufferCalls != 0 {
			t.Fatalf("unset env forced socket buffers: read_calls=%d write_calls=%d", tunable.readBufferCalls, tunable.writeBufferCalls)
		}
		waitForLogPayloads(t, sub, "socket_buffer", "carrier_id=10", "stage=default", "forced=false")
	})

	t.Run("positive value forces both buffers and logs bytes", func(t *testing.T) {
		setSocketBufferEnv(t, ptr("1048576"))
		logger := newCapturingLogger()
		sub := logger.ch

		tunable := &recordingTunableConn{recordingNetConn: newRecordingNetConn("forced")}
		tuneNowhereTCPConn(&Config{logger: logger}, tunable, 11, "forced")

		if tunable.readBuffer != 1048576 || tunable.writeBuffer != 1048576 {
			t.Fatalf("buffers = read:%d write:%d, want 1048576", tunable.readBuffer, tunable.writeBuffer)
		}
		if tunable.readBufferCalls != 1 || tunable.writeBufferCalls != 1 {
			t.Fatalf("buffer setter calls = read:%d write:%d, want 1 each", tunable.readBufferCalls, tunable.writeBufferCalls)
		}
		waitForLogPayloads(t, sub, "socket_buffer", "carrier_id=11", "stage=forced", "forced=true", "bytes=1048576")
	})

	for _, tc := range []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "zero", value: "0"},
		{name: "negative", value: "-1"},
		{name: "invalid", value: "abc"},
	} {
		t.Run(tc.name+" value keeps autotuning", func(t *testing.T) {
			setSocketBufferEnv(t, ptr(tc.value))
			logger := newCapturingLogger()
			sub := logger.ch

			tunable := &recordingTunableConn{recordingNetConn: newRecordingNetConn(tc.name)}
			tuneNowhereTCPConn(&Config{logger: logger}, tunable, 12, tc.name)

			if tunable.readBufferCalls != 0 || tunable.writeBufferCalls != 0 {
				t.Fatalf("env %q forced socket buffers: read_calls=%d write_calls=%d", tc.value, tunable.readBufferCalls, tunable.writeBufferCalls)
			}
			if tc.value == "abc" || tc.value == "-1" {
				waitForLogPayloads(t, sub, "socket_buffer_invalid", "value="+tc.value)
			}
			waitForLogPayloads(t, sub, "socket_buffer", "carrier_id=12", "stage="+tc.name, "forced=false")
		})
	}
}

func TestTuneNowhereTCPConnKeepsRealTCPConnUsable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		if _, err := conn.Read(buf); err != nil {
			serverDone <- err
			return
		}
		_, err = conn.Write([]byte{buf[0] + 1})
		serverDone <- err
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	tuneNowhereTCPConn(nil, conn, 4, "real_tcp")

	if _, err := conn.Write([]byte{41}); err != nil {
		t.Fatalf("Write after tuning: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("Read after tuning: %v", err)
	}
	if buf[0] != 42 {
		t.Fatalf("response = %d, want 42", buf[0])
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestTCPPoolFreshAndAsymmetricLanesDoNotWarnIllegalTransition(t *testing.T) {
	logger := newCapturingLogger()
	sub := logger.ch

	dialer := &recordingTCPDialer{}
	cfg := testTCPConfig(t, dialer, logger)
	pool := NewTCPPool(cfg, 0)
	defer pool.Close()

	conn, err := pool.Acquire(context.Background(), "example.com:443", TCPRelayTCP)
	if err != nil {
		t.Fatalf("Acquire fresh: %v", err)
	}
	_ = conn.Close()

	header := wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		FlowID:   42,
		Kind:     wire.FlowKindTCP,
		Uplink:   wire.CarrierTCP,
		Downlink: wire.CarrierUDP,
	}
	flowConn, err := pool.AcquireFlowHalf(context.Background(), "example.com:443", header)
	if err != nil {
		t.Fatalf("AcquireFlowHalf: %v", err)
	}
	_ = flowConn.Close()

	uotHeader := wire.FlowHeader{
		Role:     wire.FlowRoleAttach,
		FlowID:   43,
		Kind:     wire.FlowKindUDP,
		Uplink:   wire.CarrierUDP,
		Downlink: wire.CarrierTCP,
	}
	uotConn, err := pool.AcquireUDPFlowHalf(context.Background(), "example.com:443", uotHeader)
	if err != nil {
		t.Fatalf("AcquireUDPFlowHalf: %v", err)
	}
	_ = uotConn.Close()

	payloads := collectLogPayloads(sub, 50*time.Millisecond)
	for _, payload := range payloads {
		if strings.Contains(payload, "illegal transition") {
			t.Fatalf("unexpected illegal transition log: %s", payload)
		}
	}
}

func TestTCPPoolResizeEvictAndCloseDropIdleCarriers(t *testing.T) {
	dialer := &recordingTCPDialer{}
	pool := NewTCPPool(testTCPConfig(t, dialer), 3)
	for i := 0; i < 3; i++ {
		pool.prepareOne()
	}
	waitPoolIdle(t, pool, 3)

	pool.Resize(1)
	waitPoolIdle(t, pool, 1)
	closedAfterResize := 0
	for _, conn := range dialer.snapshot() {
		if conn.closed() {
			closedAfterResize++
		}
	}
	if closedAfterResize != 2 {
		t.Fatalf("Resize closed %d idle carriers, want 2", closedAfterResize)
	}

	pool.mu.Lock()
	remaining := pool.idle[0]
	pool.mu.Unlock()
	pool.evict(remaining)
	waitPoolIdle(t, pool, 0)
	if !remaining.conn.(*recordingNetConn).closed() {
		t.Fatalf("TTL eviction did not close the idle carrier")
	}

	pool.prepareOne()
	waitPoolIdle(t, pool, 1)
	pool.Close()
	for _, conn := range dialer.snapshot() {
		if !conn.closed() {
			t.Fatalf("Close left idle carrier %s open", conn.name)
		}
	}
}

func testTCPConfig(t *testing.T, dialer TCPDialer, loggers ...*capturingLogger) *Config {
	t.Helper()
	spec, err := wire.BuildEffectiveSpec("k", "auto", "now/1")
	if err != nil {
		t.Fatalf("BuildEffectiveSpec: %v", err)
	}
	cfg, err := NewConfig(TCPOptions{
		Address: "127.0.0.1:1", Spec: spec, Key: "k", Dialer: dialer, TLSDialer: passthroughTLSDialer{},
	})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if len(loggers) > 0 && loggers[0] != nil {
		cfg.logger = loggers[0]
	}
	return cfg
}

func setSocketBufferEnv(t *testing.T, value *string) {
	t.Helper()
	old, ok := os.LookupEnv("NOWHERE_TCP_SOCKET_BUFFER")
	if value == nil {
		if err := os.Unsetenv("NOWHERE_TCP_SOCKET_BUFFER"); err != nil {
			t.Fatalf("Unsetenv: %v", err)
		}
	} else if err := os.Setenv("NOWHERE_TCP_SOCKET_BUFFER", *value); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	t.Cleanup(func() {
		if ok {
			_ = os.Setenv("NOWHERE_TCP_SOCKET_BUFFER", old)
		} else {
			_ = os.Unsetenv("NOWHERE_TCP_SOCKET_BUFFER")
		}
	})
}

func ptr(s string) *string {
	return &s
}

func waitForLogPayload(t *testing.T, sub <-chan string, needle string) string {
	t.Helper()
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case event := <-sub:
			if strings.Contains(event, needle) {
				return event
			}
		case <-deadline:
			t.Fatalf("timed out waiting for log payload containing %q", needle)
		}
	}
}

func waitForLogPayloads(t *testing.T, sub <-chan string, needles ...string) string {
	t.Helper()
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case event := <-sub:
			match := true
			for _, needle := range needles {
				if !strings.Contains(event, needle) {
					match = false
					break
				}
			}
			if match {
				return event
			}
		case <-deadline:
			t.Fatalf("timed out waiting for log payload containing %q", strings.Join(needles, ", "))
		}
	}
}

func assertOpenTimingFields(t *testing.T, payload string, wants ...string) {
	t.Helper()
	for _, want := range append([]string{
		"flow_id=",
		"carrier_id=",
		"stage=",
		"network=",
		"target=",
		"outcome=",
		"raw_dial_ms=",
		"tls_ms=",
		"auth_write_ms=",
		"request_write_ms=",
		"open_total_ms=",
	}, wants...) {
		if !strings.Contains(payload, want) {
			t.Fatalf("open_timing log %q missing %q", payload, want)
		}
	}
}

func collectLogPayloads(sub <-chan string, quietFor time.Duration) []string {
	var payloads []string
	timer := time.NewTimer(quietFor)
	defer timer.Stop()
	for {
		select {
		case event := <-sub:
			payloads = append(payloads, event)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(quietFor)
		case <-timer.C:
			return payloads
		}
	}
}

func waitPoolIdle(t *testing.T, pool *TCPPool, want int) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		pool.mu.Lock()
		got := len(pool.idle)
		preparing := pool.preparing
		pool.mu.Unlock()
		if got == want && preparing == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	pool.mu.Lock()
	got := len(pool.idle)
	preparing := pool.preparing
	pool.mu.Unlock()
	t.Fatalf("idle pool size = %d preparing=%d, want idle=%d preparing=0", got, preparing, want)
}

func trackedRecordingConn(t *testing.T, conn net.Conn) *recordingNetConn {
	t.Helper()
	tracked, ok := conn.(*trackedConn)
	if !ok {
		t.Fatalf("conn type = %T, want *trackedConn", conn)
	}
	inner, ok := tracked.Conn.(*recordingNetConn)
	if !ok {
		t.Fatalf("tracked inner conn type = %T, want *recordingNetConn", tracked.Conn)
	}
	return inner
}

type recordingTCPDialer struct {
	mu     sync.Mutex
	conns  []*recordingNetConn
	queued []*recordingNetConn
	nextID int
}

func (d *recordingTCPDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	var conn *recordingNetConn
	if len(d.queued) > 0 {
		conn = d.queued[0]
		d.queued = d.queued[1:]
	} else {
		d.nextID++
		conn = newRecordingNetConn("conn")
		conn.name = conn.name + "-" + strconv.Itoa(d.nextID)
	}
	d.conns = append(d.conns, conn)
	d.mu.Unlock()
	return conn, nil
}

func (d *recordingTCPDialer) connAt(i int) *recordingNetConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conns[i]
}

func (d *recordingTCPDialer) snapshot() []*recordingNetConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*recordingNetConn, len(d.conns))
	copy(out, d.conns)
	return out
}

type parallelDialer struct {
	total      int
	allStarted chan struct{}
	release    chan struct{}
	once       sync.Once

	mu        sync.Mutex
	started   int
	active    int
	maxActive int
	nextID    int
}

func newParallelDialer(total int) *parallelDialer {
	return &parallelDialer{
		total:      total,
		allStarted: make(chan struct{}),
		release:    make(chan struct{}),
	}
}

func (d *parallelDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.started++
	d.active++
	if d.active > d.maxActive {
		d.maxActive = d.active
	}
	if d.started == d.total {
		d.once.Do(func() { close(d.allStarted) })
	}
	d.nextID++
	id := d.nextID
	d.mu.Unlock()

	select {
	case <-d.release:
	case <-ctx.Done():
		d.mu.Lock()
		d.active--
		d.mu.Unlock()
		return nil, ctx.Err()
	}

	d.mu.Lock()
	d.active--
	d.mu.Unlock()
	return newRecordingNetConn("fresh-" + strconv.Itoa(id)), nil
}

func (d *parallelDialer) startedCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.started
}

func (d *parallelDialer) maxActiveCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.maxActive
}

type freshDialContextKey struct{}

type blockingPrepareDialer struct {
	warmStarted chan struct{}
	releaseWarm chan struct{}
	once        sync.Once

	mu     sync.Mutex
	conns  []*recordingNetConn
	nextID int
}

func newBlockingPrepareDialer() *blockingPrepareDialer {
	return &blockingPrepareDialer{
		warmStarted: make(chan struct{}),
		releaseWarm: make(chan struct{}),
	}
}

func (d *blockingPrepareDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.nextID++
	id := d.nextID
	d.mu.Unlock()
	if ctx.Value(freshDialContextKey{}) != true {
		d.once.Do(func() { close(d.warmStarted) })
		select {
		case <-d.releaseWarm:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	conn := newRecordingNetConn("conn-" + strconv.Itoa(id))
	d.mu.Lock()
	d.conns = append(d.conns, conn)
	d.mu.Unlock()
	return conn, nil
}

func (d *blockingPrepareDialer) snapshot() []*recordingNetConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*recordingNetConn, len(d.conns))
	copy(out, d.conns)
	return out
}

type passthroughTLSDialer struct{}

func (passthroughTLSDialer) DialTLSConn(ctx context.Context, c net.Conn) (net.Conn, error) {
	return c, nil
}

type recordingNetConn struct {
	name        string
	failWriteAt int

	mu         sync.Mutex
	writeCount int
	closedFlag bool
}

func newRecordingNetConn(name string) *recordingNetConn {
	return &recordingNetConn{name: name}
}

func (c *recordingNetConn) Read([]byte) (int, error) { return 0, errors.New("test conn: no reads") }
func (c *recordingNetConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closedFlag {
		return 0, net.ErrClosed
	}
	c.writeCount++
	if c.failWriteAt > 0 && c.writeCount == c.failWriteAt {
		return 0, errors.New("test conn: write failed")
	}
	return len(p), nil
}
func (c *recordingNetConn) Close() error {
	c.mu.Lock()
	c.closedFlag = true
	c.mu.Unlock()
	return nil
}
func (c *recordingNetConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *recordingNetConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *recordingNetConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingNetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingNetConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordingNetConn) closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closedFlag
}

type recordingTunableConn struct {
	*recordingNetConn
	err error

	noDelay         bool
	keepAlive       bool
	keepAlivePeriod time.Duration
	readBuffer      int
	writeBuffer     int

	noDelayCalls     int
	keepAliveCalls   int
	readBufferCalls  int
	writeBufferCalls int
}

func (c *recordingTunableConn) SetNoDelay(enabled bool) error {
	c.noDelayCalls++
	c.noDelay = enabled
	return c.err
}

func (c *recordingTunableConn) SetKeepAlive(enabled bool) error {
	c.keepAliveCalls++
	c.keepAlive = enabled
	return c.err
}

func (c *recordingTunableConn) SetKeepAlivePeriod(period time.Duration) error {
	c.keepAlivePeriod = period
	return c.err
}

func (c *recordingTunableConn) SetReadBuffer(bytes int) error {
	c.readBufferCalls++
	c.readBuffer = bytes
	return c.err
}

func (c *recordingTunableConn) SetWriteBuffer(bytes int) error {
	c.writeBufferCalls++
	c.writeBuffer = bytes
	return c.err
}

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }
