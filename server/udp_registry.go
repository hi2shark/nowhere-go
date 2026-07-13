package server

import "github.com/hi2shark/nowhere-go/wire"

type legacyUDPKey struct {
	flowID uint64
	target string
}

type compactUDPEntry struct {
	flowID     uint64
	generation uint64
	target     string
	downlink   wire.Carrier
	lease      *compactGenerationLease
	symmetric  *compactUDPFlow
	pair       *udpPairHandle
	revoking   bool
}

type compactEntryState uint8

const (
	compactEntryAbsent compactEntryState = iota
	compactEntryActive
	compactEntryRetiring
)

type udpRegistryState struct {
	compact        map[uint64]*compactUDPEntry
	legacy         map[legacyUDPKey]*legacyUDPFlow
	activeFlows    int
	nextGeneration uint64
}

func newUDPRegistryState() udpRegistryState {
	return udpRegistryState{
		compact: make(map[uint64]*compactUDPEntry),
		legacy:  make(map[legacyUDPKey]*legacyUDPFlow),
	}
}

func (s *portalSession) reserveCompactEntry(entry *compactUDPEntry) bool {
	if entry == nil || entry.flowID == 0 {
		return false
	}
	if entry.lease == nil {
		entry.lease = &compactGenerationLease{flowID: entry.flowID, send: s.SendDatagram}
	}
	s.mu.Lock()
	if s.closed || s.udp.activeFlows >= s.Handler.config.limits.QUICFlowsPerSession {
		s.mu.Unlock()
		return false
	}
	if _, exists := s.udp.compact[entry.flowID]; exists {
		s.mu.Unlock()
		return false
	}
	s.udp.nextGeneration++
	if s.udp.nextGeneration == 0 {
		s.udp.nextGeneration++
	}
	entry.generation = s.udp.nextGeneration
	if !entry.lease.bindWithFinalizer(entry.generation, func() {
		s.finalizeCompactEntry(entry)
	}) {
		s.mu.Unlock()
		return false
	}
	if entry.symmetric != nil {
		entry.symmetric.generation = entry.generation
		entry.symmetric.lease = entry.lease
	}
	s.udp.compact[entry.flowID] = entry
	s.udp.activeFlows++
	s.mu.Unlock()
	if entry.symmetric != nil {
		entry.symmetric.resetIdle()
	}
	return true
}

func (s *portalSession) lookupCompactEntry(flowID uint64) (*compactUDPEntry, compactEntryState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.udp.compact[flowID]
	if entry == nil {
		return nil, compactEntryAbsent
	}
	if entry.revoking {
		return entry, compactEntryRetiring
	}
	return entry, compactEntryActive
}

func (s *portalSession) getCompactEntry(flowID uint64) *compactUDPEntry {
	entry, state := s.lookupCompactEntry(flowID)
	if state != compactEntryActive {
		return nil
	}
	return entry
}

func (s *portalSession) detachCompactEntry(flowID, generation uint64) (*compactUDPEntry, bool) {
	entry, ok := s.retireCompactEntry(flowID, generation, false)
	if ok && entry.lease != nil {
		entry.lease.MarkCleanupDone()
	}
	return entry, ok
}

func (s *portalSession) retireCompactEntry(flowID, generation uint64, terminalRequired bool) (*compactUDPEntry, bool) {
	s.mu.Lock()
	entry := s.udp.compact[flowID]
	if entry == nil || entry.generation != generation || entry.revoking {
		s.mu.Unlock()
		return nil, false
	}
	entry.revoking = true
	s.mu.Unlock()

	if entry.lease == nil || !entry.lease.Retire(entry.generation, terminalRequired) {
		return nil, false
	}
	return entry, true
}

func (s *portalSession) finalizeCompactEntry(entry *compactUDPEntry) {
	if entry == nil {
		return
	}
	s.mu.Lock()
	current := s.udp.compact[entry.flowID]
	if current == entry && current.generation == entry.generation && current.revoking {
		delete(s.udp.compact, entry.flowID)
		s.releaseUDPFlowLocked()
	}
	s.mu.Unlock()
}

func (s *portalSession) reserveLegacyFlow(flow *legacyUDPFlow) bool {
	if flow == nil {
		return false
	}
	s.mu.Lock()
	if s.closed || s.udp.activeFlows >= s.Handler.config.limits.QUICFlowsPerSession {
		s.mu.Unlock()
		return false
	}
	if _, exists := s.udp.legacy[flow.key]; exists {
		s.mu.Unlock()
		return false
	}
	s.udp.legacy[flow.key] = flow
	s.udp.activeFlows++
	s.mu.Unlock()
	flow.resetIdle()
	return true
}

func (s *portalSession) getLegacyFlow(key legacyUDPKey) *legacyUDPFlow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udp.legacy[key]
}

func (s *portalSession) detachLegacyFlow(key legacyUDPKey, flow *legacyUDPFlow) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.udp.legacy[key]; current == nil || current != flow {
		return false
	}
	delete(s.udp.legacy, key)
	s.releaseUDPFlowLocked()
	return true
}

func (s *portalSession) putFlow(flowID uint64, flow *compactUDPFlow) bool {
	if flow == nil || flowID != flow.flowID {
		return false
	}
	entry := &compactUDPEntry{
		flowID:    flowID,
		target:    flow.target,
		downlink:  flow.downlink,
		lease:     &compactGenerationLease{flowID: flowID, send: s.SendDatagram},
		symmetric: flow,
	}
	return s.reserveCompactEntry(entry)
}

func (s *portalSession) releaseUDPFlowLocked() {
	if s.udp.activeFlows > 0 {
		s.udp.activeFlows--
	}
}
