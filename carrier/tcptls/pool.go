package tcptls

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/carrier"
	"github.com/hi2shark/nowhere-go/carrier/dialgate"
	"github.com/hi2shark/nowhere-go/wire"
)

const warmTTL = 30 * time.Second

func loggerFrom(cfg *Config) carrier.Logger {
	if cfg != nil && cfg.logger != nil {
		return cfg.logger
	}
	return carrier.NopLogger{}
}

func (p *TCPPool) logger() carrier.Logger {
	return loggerFrom(p.cfg)
}

const (
	nowhereTCPSocketBufferEnv = "NOWHERE_TCP_SOCKET_BUFFER"
	tcpKeepAlivePeriod        = 30 * time.Second
)

type warmConn struct {
	conn    net.Conn
	carrier *carrierInfo
	expiry  *time.Timer
}

type poolSnapshot struct {
	idle      int
	preparing int
	target    int
}

// TCPPool holds warm authenticated TLS/TCP connections.
// Idle entries are pre-auth only; after a request frame the carrier is consumed
// (no Release/Put). Each Acquire pops at most one connection under p.mu.
type TCPPool struct {
	cfg       *Config
	target    int
	dialSlots chan struct{}
	dialGate  *dialgate.Gate
	mu        sync.Mutex
	idle      []*warmConn
	preparing int
	closed    bool

	warmFailCount int
	nextWarmRetry time.Time
}

func NewTCPPool(cfg *Config, target int) *TCPPool {
	if cfg == nil || cfg.spec == nil || cfg.dialer == nil || cfg.tlsDialer == nil {
		return nil
	}
	if target < 0 {
		target = 0
	}
	if target > maxPoolSize {
		target = maxPoolSize
	}
	maxDials := cfg.maxConcurrentDials
	if maxDials <= 0 {
		maxDials = DefaultMaxConcurrentDials
	}
	return &TCPPool{
		cfg:       cfg,
		target:    target,
		dialSlots: make(chan struct{}, maxDials),
		dialGate: dialgate.New(dialgate.Options{
			Initial: cfg.DialBackoffInitial(),
			Max:     cfg.DialBackoffMax(),
		}),
	}
}

func (p *TCPPool) Target() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.target
}

func (p *TCPPool) Resize(target int) {
	if target < 0 {
		target = 0
	}
	if target > maxPoolSize {
		target = maxPoolSize
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.target = target
	for len(p.idle) > target {
		wc := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if wc.expiry != nil {
			wc.expiry.Stop()
		}
		wc.carrier.transition(stateClosed)
		p.logger().Debugf("[Nowhere] [carrier] pool_resize_drop carrier_id=%d new_target=%d", wc.carrier.id, target)
		_ = wc.conn.Close()
	}
}

func (p *TCPPool) Acquire(ctx context.Context, dest string, mode TCPRelayMode) (net.Conn, error) {
	conn, err := p.acquire(ctx, dest, mode)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (p *TCPPool) acquire(ctx context.Context, dest string, mode TCPRelayMode) (net.Conn, error) {
	start := time.Now()
	flowID := allocFlowID()
	network := "tcp"
	if mode == TCPRelayUoT {
		network = "udp"
	}
	p.logger().Debugf("[Nowhere] [carrier] flow_start flow_id=%d network=%s target=%s", flowID, network, dest)

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("nowhere: tcp pool closed")
	}
	var selected *warmConn
	if len(p.idle) > 0 {
		wc := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if wc.expiry != nil {
			wc.expiry.Stop()
		}
		selected = wc
	}
	snapshot := p.snapshotLocked()
	p.mu.Unlock()

	if selected != nil {
		selected.carrier.transition(stateBorrowed)
		p.logger().Debugf("[Nowhere] [carrier] borrow_warm flow_id=%d carrier_id=%d pool_remaining=%d",
			flowID, selected.carrier.id, func() int { p.mu.Lock(); n := len(p.idle); p.mu.Unlock(); return n }())
		conn, err := activatePrepared(selected.conn, selected.carrier, flowID, p.cfg, dest, mode)
		if err != nil {
			p.logger().Debugf("[Nowhere] [carrier] activate_warm_failed flow_id=%d carrier_id=%d err=%v (falling back to fresh)",
				flowID, selected.carrier.id, err)
			selected.carrier.transition(stateClosed)
			_ = selected.conn.Close()
			p.mu.Lock()
			snapshot = p.snapshotLocked()
			p.mu.Unlock()
		} else {
			p.maybeStartPrepare(p.replenishBudget(true))
			logPoolAcquire(p.cfg, "warm", flowID, selected.carrier.id, snapshot, start)
			return conn, nil
		}
	}

	// Fresh-first: never start warm prepare before a successful business dial.
	// This avoids ~2x amplification when the portal is unreachable.
	outcome := "fresh"
	if selected != nil {
		outcome = "warm_failed_fresh"
	}
	conn, err := p.openFresh(ctx, flowID, dest, mode, outcome)
	if err != nil {
		return nil, err
	}
	p.maybeStartPrepare(p.replenishBudget(false))
	logPoolAcquire(p.cfg, outcome, flowID, carrierIDOf(conn), snapshot, start)
	return conn, nil
}

func (p *TCPPool) snapshotLocked() poolSnapshot {
	return poolSnapshot{
		idle:      len(p.idle),
		preparing: p.preparing,
		target:    p.target,
	}
}

func (p *TCPPool) replenishBudget(afterWarmHit bool) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.replenishBudgetLocked(afterWarmHit)
}

func (p *TCPPool) replenishBudgetLocked(afterWarmHit bool) int {
	max := 0
	if afterWarmHit {
		max = 2
	} else if len(p.idle)+p.preparing == 0 {
		max = 1
	}
	if max <= 0 || p.target <= 0 {
		return 0
	}
	if !p.warmAllowedLocked() {
		return 0
	}
	room := p.target - (len(p.idle) + p.preparing)
	if room <= 0 {
		return 0
	}
	if max > room {
		return room
	}
	return max
}

func (p *TCPPool) maybeStartPrepare(count int) {
	if count <= 0 {
		return
	}
	p.mu.Lock()
	if p.closed || p.target <= 0 {
		p.mu.Unlock()
		return
	}
	if !p.warmAllowedLocked() {
		delay := time.Until(p.nextWarmRetry)
		p.mu.Unlock()
		p.logger().Debugf("[Nowhere] [carrier] warm_backoff delay_ms=%d", delay.Milliseconds())
		return
	}
	room := p.target - (len(p.idle) + p.preparing)
	if room <= 0 {
		p.mu.Unlock()
		return
	}
	if count > room {
		count = room
	}
	p.mu.Unlock()
	for i := 0; i < count; i++ {
		go p.prepareOne()
	}
}

func (p *TCPPool) warmAllowedLocked() bool {
	if p.nextWarmRetry.IsZero() {
		return true
	}
	return !time.Now().Before(p.nextWarmRetry)
}

func (p *TCPPool) noteWarmFailureLocked() {
	p.warmFailCount++
	base := p.cfg.warmBackoffInitial
	if base <= 0 {
		base = DefaultWarmBackoffInitial
	}
	max := p.cfg.warmBackoffMax
	if max <= 0 {
		max = DefaultWarmBackoffMax
	}
	delay := base
	for i := 1; i < p.warmFailCount; i++ {
		if delay >= max {
			delay = max
			break
		}
		next := delay * 2
		if next > max || next < delay {
			delay = max
			break
		}
		delay = next
	}
	delay = jitterDuration(delay)
	if delay > max {
		delay = max
	}
	p.nextWarmRetry = time.Now().Add(delay)
	p.logger().Debugf("[Nowhere] [carrier] warm_prepare_failed fail_count=%d next_retry_ms=%d",
		p.warmFailCount, delay.Milliseconds())
}

func (p *TCPPool) clearWarmBackoffLocked() {
	p.warmFailCount = 0
	p.nextWarmRetry = time.Time{}
}

func jitterDuration(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return base
	}
	ratio := float64(binary.BigEndian.Uint64(raw[:])) / float64(^uint64(0))
	factor := 0.8 + ratio*0.4
	return time.Duration(float64(base) * factor)
}

func (p *TCPPool) acquireDialSlot(ctx context.Context) (func(), error) {
	if p == nil || p.dialSlots == nil {
		return func() {}, nil
	}
	select {
	case p.dialSlots <- struct{}{}:
		return func() { <-p.dialSlots }, nil
	case <-ctx.Done():
		p.logger().Debugf("[Nowhere] [carrier] dial_throttled outcome=context_canceled")
		return nil, ctx.Err()
	}
}

func (p *TCPPool) tryAcquireDialSlot() (func(), bool) {
	if p == nil || p.dialSlots == nil {
		return func() {}, true
	}
	select {
	case p.dialSlots <- struct{}{}:
		return func() { <-p.dialSlots }, true
	default:
		return nil, false
	}
}

func (p *TCPPool) openFresh(ctx context.Context, flowID uint64, dest string, mode TCPRelayMode, outcome string) (net.Conn, error) {
	var conn net.Conn
	err := p.runPortalDial(ctx, func(ctx context.Context) error {
		release, err := p.acquireDialSlot(ctx)
		if err != nil {
			return err
		}
		defer release()
		c, err := openFresh(ctx, p.cfg, flowID, dest, mode, outcome)
		if err != nil {
			return err
		}
		conn = c
		return nil
	})
	return conn, err
}

// DialAttempts returns portal establish attempts observed by the dial gate (tests).
func (p *TCPPool) DialAttempts() uint64 {
	if p == nil || p.dialGate == nil {
		return 0
	}
	return p.dialGate.Attempts()
}

func (p *TCPPool) runPortalDial(ctx context.Context, fn func(context.Context) error) error {
	if p == nil || p.dialGate == nil {
		return fn(ctx)
	}
	return p.dialGate.Run(ctx, fn)
}

func logPoolAcquire(cfg *Config, outcome string, flowID uint64, carrierID uint64, snapshot poolSnapshot, start time.Time) {
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] pool_acquire outcome=%s flow_id=%d carrier_id=%d idle=%d preparing=%d target=%d elapsed_ms=%d",
		outcome, flowID, carrierID, snapshot.idle, snapshot.preparing, snapshot.target, time.Since(start).Milliseconds())
}

func carrierIDOf(conn net.Conn) uint64 {
	if tracked, ok := conn.(*trackedConn); ok && tracked.carrier != nil {
		return tracked.carrier.id
	}
	return 0
}

func (p *TCPPool) Close() {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, wc := range idle {
		if wc.expiry != nil {
			wc.expiry.Stop()
		}
		wc.carrier.transition(stateClosed)
		_ = wc.conn.Close()
	}
}

func (p *TCPPool) prepareOne() {
	p.mu.Lock()
	if p.closed || p.preparing+len(p.idle) >= p.target || !p.warmAllowedLocked() {
		p.mu.Unlock()
		return
	}
	p.preparing++
	p.mu.Unlock()

	release, ok := p.tryAcquireDialSlot()
	if !ok {
		p.mu.Lock()
		p.preparing--
		p.mu.Unlock()
		p.logger().Debugf("[Nowhere] [carrier] dial_throttled outcome=warm_skipped")
		return
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	conn, ci, err := prepare(ctx, p.cfg)
	cancel()
	if err != nil {
		p.logger().Debugf("[Nowhere] warm prepare failed: %v", err)
		p.mu.Lock()
		p.preparing--
		p.noteWarmFailureLocked()
		p.mu.Unlock()
		return
	}

	wc := &warmConn{conn: conn, carrier: ci}
	p.mu.Lock()
	p.preparing--
	p.clearWarmBackoffLocked()
	if p.closed || len(p.idle) >= p.target {
		p.mu.Unlock()
		ci.transition(stateClosed)
		_ = conn.Close()
		return
	}
	wc.expiry = time.AfterFunc(warmTTL, func() { p.evict(wc) })
	p.idle = append(p.idle, wc)
	ci.transition(stateAuthenticatedIdle)
	p.logger().Debugf("[Nowhere] [carrier] warm_ready carrier_id=%d pool_size=%d", ci.id, len(p.idle))
	p.mu.Unlock()
}

func dialAddr(cfg *Config) string {
	if cfg.connectAddress != "" {
		return cfg.connectAddress
	}
	return cfg.address
}

func (p *TCPPool) evict(wc *warmConn) {
	p.mu.Lock()
	removed := false
	for i, c := range p.idle {
		if c == wc {
			p.idle = append(p.idle[:i], p.idle[i+1:]...)
			removed = true
			break
		}
	}
	p.mu.Unlock()
	if !removed {
		return
	}
	if wc.expiry != nil {
		wc.expiry.Stop()
	}
	wc.carrier.transition(stateClosed)
	p.logger().Debugf("[Nowhere] [carrier] warm_evicted carrier_id=%d (ttl expired)", wc.carrier.id)
	_ = wc.conn.Close()
}

type openTiming struct {
	start        time.Time
	rawDial      time.Duration
	tlsHandshake time.Duration
	authWrite    time.Duration
	requestWrite time.Duration
}

func newOpenTiming() openTiming {
	return openTiming{start: time.Now()}
}

func logOpenTiming(cfg *Config, outcome string, flowID uint64, carrierID uint64, stage string, network string, target string, timing openTiming) {
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] open_timing outcome=%s flow_id=%d carrier_id=%d stage=%s network=%s target=%s raw_dial_ms=%d tls_ms=%d auth_write_ms=%d request_write_ms=%d open_total_ms=%d",
		outcome,
		flowID,
		carrierID,
		stage,
		network,
		target,
		timing.rawDial.Milliseconds(),
		timing.tlsHandshake.Milliseconds(),
		timing.authWrite.Milliseconds(),
		timing.requestWrite.Milliseconds(),
		time.Since(timing.start).Milliseconds())
}

func writeFullTimed(conn net.Conn, payload []byte) (time.Duration, error) {
	start := time.Now()
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if n > 0 {
			payload = payload[n:]
		}
		if err != nil {
			return time.Since(start), err
		}
		if n == 0 {
			return time.Since(start), io.ErrShortWrite
		}
	}
	return time.Since(start), nil
}

type noDelaySetter interface {
	SetNoDelay(bool) error
}

type keepAliveSetter interface {
	SetKeepAlive(bool) error
}

type keepAlivePeriodSetter interface {
	SetKeepAlivePeriod(time.Duration) error
}

type readBufferSetter interface {
	SetReadBuffer(int) error
}

type writeBufferSetter interface {
	SetWriteBuffer(int) error
}

func tuneNowhereTCPConn(cfg *Config, conn net.Conn, carrierID uint64, stage string) {
	log := loggerFrom(cfg)
	if setter, ok := conn.(noDelaySetter); ok {
		if err := setter.SetNoDelay(true); err != nil {
			log.Debugf("[Nowhere] [carrier] tcp_tune_failed carrier_id=%d stage=%s option=no_delay err=%v", carrierID, stage, err)
		}
	}
	if setter, ok := conn.(keepAliveSetter); ok {
		if err := setter.SetKeepAlive(true); err != nil {
			loggerFrom(cfg).Debugf("[Nowhere] [carrier] tcp_tune_failed carrier_id=%d stage=%s option=keepalive err=%v", carrierID, stage, err)
		}
	}
	if setter, ok := conn.(keepAlivePeriodSetter); ok {
		if err := setter.SetKeepAlivePeriod(tcpKeepAlivePeriod); err != nil {
			loggerFrom(cfg).Debugf("[Nowhere] [carrier] tcp_tune_failed carrier_id=%d stage=%s option=keepalive_period err=%v", carrierID, stage, err)
		}
	}
	bufferBytes, forced, invalidValue := configuredTCPSocketBuffer()
	if invalidValue != "" {
		loggerFrom(cfg).Debugf("[Nowhere] [carrier] socket_buffer_invalid carrier_id=%d stage=%s value=%s", carrierID, stage, invalidValue)
	}
	if !forced {
		loggerFrom(cfg).Debugf("[Nowhere] [carrier] socket_buffer carrier_id=%d stage=%s forced=false", carrierID, stage)
		return
	}
	if setter, ok := conn.(readBufferSetter); ok {
		if err := setter.SetReadBuffer(bufferBytes); err != nil {
			loggerFrom(cfg).Debugf("[Nowhere] [carrier] tcp_tune_failed carrier_id=%d stage=%s option=read_buffer err=%v", carrierID, stage, err)
		}
	}
	if setter, ok := conn.(writeBufferSetter); ok {
		if err := setter.SetWriteBuffer(bufferBytes); err != nil {
			loggerFrom(cfg).Debugf("[Nowhere] [carrier] tcp_tune_failed carrier_id=%d stage=%s option=write_buffer err=%v", carrierID, stage, err)
		}
	}
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] socket_buffer carrier_id=%d stage=%s forced=true bytes=%d", carrierID, stage, bufferBytes)
}

func configuredTCPSocketBuffer() (bytes int, forced bool, invalidValue string) {
	raw, ok := os.LookupEnv(nowhereTCPSocketBufferEnv)
	if !ok {
		return 0, false, ""
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, false, ""
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, false, raw
	}
	if n == 0 {
		return 0, false, ""
	}
	return n, true, ""
}

// prepare dials, TLS-handshakes, and authenticates. Caller moves to authenticatedIdle.
func prepare(ctx context.Context, cfg *Config) (net.Conn, *carrierInfo, error) {
	ci := newCarrierInfo(loggerFrom(cfg))
	timing := newOpenTiming()
	stage := "tls"
	target := dialAddr(cfg)
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] dial_start carrier_id=%d stage=tls", ci.id)
	rawDialStart := time.Now()
	raw, err := cfg.dialer.DialContext(ctx, "tcp", dialAddr(cfg))
	timing.rawDial = time.Since(rawDialStart)
	if err != nil {
		ci.transition(stateClosed)
		logOpenTiming(cfg, "warm_prepare_failed", 0, ci.id, stage, "tcp", target, timing)
		return nil, nil, err
	}
	tuneNowhereTCPConn(cfg, raw, ci.id, stage)
	tlsStart := time.Now()
	tlsConn, err := cfg.tlsDialer.DialTLSConn(ctx, raw)
	timing.tlsHandshake = time.Since(tlsStart)
	if err != nil {
		_ = raw.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, "warm_prepare_failed", 0, ci.id, stage, "tcp", target, timing)
		return nil, nil, err
	}
	auth, err := tcpAuthFrame(cfg)
	if err != nil {
		_ = tlsConn.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, "warm_prepare_failed", 0, ci.id, stage, "tcp", target, timing)
		return nil, nil, err
	}
	timing.authWrite, err = writeFullTimed(tlsConn, auth)
	if err != nil {
		_ = tlsConn.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, "warm_prepare_failed", 0, ci.id, stage, "tcp", target, timing)
		return nil, nil, err
	}
	logOpenTiming(cfg, "warm_prepare", 0, ci.id, stage, "tcp", target, timing)
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] auth_ok carrier_id=%d", ci.id)
	return tlsConn, ci, nil
}

func tcpAuthFrame(cfg *Config) ([]byte, error) {
	if cfg.sessionID != (wire.SessionID{}) {
		return wire.MakeAuthFrameWithSession(cfg.key, cfg.spec, cfg.sessionID)
	}
	frame, _, err := wire.MakeAuthFrame(cfg.key, cfg.spec)
	return frame, err
}

// activatePrepared sends the request on a warm connection; carrier must not return to the pool.
func activatePrepared(conn net.Conn, ci *carrierInfo, flowID uint64, cfg *Config, dest string, mode TCPRelayMode) (net.Conn, error) {
	timing := newOpenTiming()
	network := relayNetwork(mode)
	req, err := requestPayload(cfg.spec, dest, mode)
	if err != nil {
		logOpenTiming(cfg, "warm_failed", flowID, ci.id, "warm_activate", network, dest, timing)
		return nil, err
	}
	timing.requestWrite, err = writeFullTimed(conn, req)
	if err != nil {
		logOpenTiming(cfg, "warm_failed", flowID, ci.id, "warm_activate", network, dest, timing)
		return nil, err
	}
	ci.transition(stateRequestSent)
	ci.transition(stateConsumed)
	logOpenTiming(cfg, "warm", flowID, ci.id, "warm_activate", network, dest, timing)
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] request_sent flow_id=%d carrier_id=%d target=%s consumed=true",
		flowID, ci.id, dest)
	return wrapRelay(conn, ci, flowID, mode, dest), nil
}

// openFresh dials, authenticates, and sends the request on a new connection (pool miss / disabled).
func openFresh(ctx context.Context, cfg *Config, flowID uint64, dest string, mode TCPRelayMode, outcome string) (net.Conn, error) {
	ci := newCarrierInfo(loggerFrom(cfg))
	timing := newOpenTiming()
	stage := "fresh_tls"
	network := relayNetwork(mode)
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] dial_start carrier_id=%d flow_id=%d stage=%s", ci.id, flowID, stage)
	ci.transition(stateBorrowed)
	rawDialStart := time.Now()
	raw, err := cfg.dialer.DialContext(ctx, "tcp", dialAddr(cfg))
	timing.rawDial = time.Since(rawDialStart)
	if err != nil {
		ci.transition(stateClosed)
		logOpenTiming(cfg, outcome+"_failed", flowID, ci.id, stage, network, dest, timing)
		return nil, err
	}
	tuneNowhereTCPConn(cfg, raw, ci.id, stage)
	tlsStart := time.Now()
	tlsConn, err := cfg.tlsDialer.DialTLSConn(ctx, raw)
	timing.tlsHandshake = time.Since(tlsStart)
	if err != nil {
		_ = raw.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, outcome+"_failed", flowID, ci.id, stage, network, dest, timing)
		return nil, err
	}
	auth, err := tcpAuthFrame(cfg)
	if err != nil {
		_ = tlsConn.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, outcome+"_failed", flowID, ci.id, stage, network, dest, timing)
		return nil, err
	}
	req, err := requestPayload(cfg.spec, dest, mode)
	if err != nil {
		_ = tlsConn.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, outcome+"_failed", flowID, ci.id, stage, network, dest, timing)
		return nil, err
	}
	timing.authWrite, err = writeFullTimed(tlsConn, auth)
	if err != nil {
		_ = tlsConn.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, outcome+"_failed", flowID, ci.id, stage, network, dest, timing)
		return nil, err
	}
	timing.requestWrite, err = writeFullTimed(tlsConn, req)
	if err != nil {
		_ = tlsConn.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, outcome+"_failed", flowID, ci.id, stage, network, dest, timing)
		return nil, err
	}
	ci.transition(stateRequestSent)
	ci.transition(stateConsumed)
	logOpenTiming(cfg, outcome, flowID, ci.id, stage, network, dest, timing)
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] auth_ok carrier_id=%d flow_id=%d", ci.id, flowID)
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] request_sent flow_id=%d carrier_id=%d target=%s consumed=true",
		flowID, ci.id, dest)
	return wrapRelay(tlsConn, ci, flowID, mode, dest), nil
}

func relayNetwork(mode TCPRelayMode) string {
	if mode == TCPRelayUoT {
		return "udp"
	}
	return "tcp"
}

func requestPayload(spec *wire.EffectiveSpec, dest string, mode TCPRelayMode) ([]byte, error) {
	switch mode {
	case TCPRelayUoT:
		magic, err := wire.EncodeTCPRequest(wire.UOTMagicTarget, spec)
		if err != nil {
			return nil, err
		}
		setup, err := wire.EncodeUOTSetupTarget(dest)
		if err != nil {
			return nil, err
		}
		return append(magic, setup...), nil
	default:
		return wire.EncodeTCPRequest(dest, spec)
	}
}

