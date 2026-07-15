package server

import (
	"sync"
	"time"

	"github.com/hi2shark/nowhere-go/internal/udpassembly"
	"github.com/hi2shark/nowhere-go/wire"
)

type byteBudget struct {
	mu    sync.Mutex
	limit int
	used  int
}

func (b *byteBudget) reserve(count int) bool {
	if b == nil || count < 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit > 0 && b.used+count > b.limit {
		return false
	}
	b.used += count
	return true
}

func (b *byteBudget) release(count int) {
	if b == nil || count <= 0 {
		return
	}
	b.mu.Lock()
	b.used -= count
	if b.used < 0 {
		b.used = 0
	}
	b.mu.Unlock()
}

type reassemblyKey struct {
	flowID   uint64
	packetID uint32
}

type assemblySlot struct {
	created  time.Time
	packet   *udpassembly.Packet
	reserved int
}

type udpReassembler struct {
	mu       sync.Mutex
	maxSlots int
	ttl      time.Duration
	slots    map[reassemblyKey]*assemblySlot
	order    []reassemblyKey
	budget   *byteBudget
	closed   bool
}

type reassemblyOutcome struct {
	Packet   []byte
	Complete bool
	Dropped  bool
	Release  func()
}

func newUDPReassembler(maxSlots int, ttl time.Duration, budget *byteBudget) *udpReassembler {
	if maxSlots <= 0 {
		maxSlots = 1
	}
	if ttl <= 0 {
		ttl = time.Second
	}
	if budget == nil {
		budget = &byteBudget{}
	}
	return &udpReassembler{
		maxSlots: maxSlots,
		ttl:      ttl,
		slots:    make(map[reassemblyKey]*assemblySlot),
		budget:   budget,
	}
}

func (r *udpReassembler) Push(flowID uint64, fragment wire.UDPFragment, now time.Time) reassemblyOutcome {
	if r == nil || flowID == 0 {
		return reassemblyOutcome{Dropped: true}
	}
	key := reassemblyKey{flowID: flowID, packetID: fragment.PacketID}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return reassemblyOutcome{Dropped: true}
	}
	r.expireLocked(now)

	slot := r.slots[key]
	if slot == nil {
		if !r.makeRoomLocked() {
			return reassemblyOutcome{Dropped: true}
		}
		packet, result, err := udpassembly.NewPacket(fragment)
		if err != nil {
			return reassemblyOutcome{Dropped: true}
		}
		reserved := result.AddedBytes
		if result.Complete && reserved == 0 {
			reserved = 1
		}
		if !r.budget.reserve(reserved) {
			return reassemblyOutcome{Dropped: true}
		}
		slot = &assemblySlot{created: now, packet: packet, reserved: reserved}
		r.slots[key] = slot
		r.order = append(r.order, key)
		if result.Complete {
			return r.completeLocked(key, slot)
		}
		return reassemblyOutcome{}
	}
	if slot.packet == nil || slot.packet.Complete() {
		return reassemblyOutcome{}
	}

	result, err := slot.packet.Push(fragment)
	if err != nil {
		r.removeSlotLocked(key, slot)
		return reassemblyOutcome{Dropped: true}
	}
	if result.Duplicate {
		return reassemblyOutcome{}
	}
	if !r.budget.reserve(result.AddedBytes) {
		r.removeSlotLocked(key, slot)
		return reassemblyOutcome{Dropped: true}
	}
	slot.reserved += result.AddedBytes
	if result.Complete {
		return r.completeLocked(key, slot)
	}
	return reassemblyOutcome{}
}

func (r *udpReassembler) completeLocked(key reassemblyKey, slot *assemblySlot) reassemblyOutcome {
	packet, err := slot.packet.Assemble()
	if err != nil {
		r.removeSlotLocked(key, slot)
		return reassemblyOutcome{Dropped: true}
	}
	var once sync.Once
	return reassemblyOutcome{
		Packet:   packet,
		Complete: true,
		Release: func() {
			once.Do(func() {
				r.mu.Lock()
				if current := r.slots[key]; current == slot {
					r.removeSlotLocked(key, slot)
				}
				r.mu.Unlock()
			})
		},
	}
}

func (r *udpReassembler) Expire(now time.Time) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if !r.closed {
		r.expireLocked(now)
	}
	r.mu.Unlock()
}

func (r *udpReassembler) expireLocked(now time.Time) {
	for _, key := range append([]reassemblyKey(nil), r.order...) {
		slot := r.slots[key]
		if slot == nil || slot.packet == nil || slot.packet.Complete() {
			continue
		}
		if !now.Before(slot.created.Add(r.ttl)) {
			r.removeSlotLocked(key, slot)
		}
	}
}

func (r *udpReassembler) RemoveFlow(flowID uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	for key, slot := range r.slots {
		if key.flowID == flowID {
			r.removeSlotLocked(key, slot)
		}
	}
	r.mu.Unlock()
}

func (r *udpReassembler) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	for key, slot := range r.slots {
		r.removeSlotLocked(key, slot)
	}
	r.order = nil
	r.mu.Unlock()
}

func (r *udpReassembler) makeRoomLocked() bool {
	if len(r.slots) < r.maxSlots {
		return true
	}
	for _, key := range r.order {
		slot := r.slots[key]
		if slot == nil || slot.packet == nil || slot.packet.Complete() {
			continue
		}
		r.removeSlotLocked(key, slot)
		return true
	}
	return false
}

func (r *udpReassembler) removeSlotLocked(key reassemblyKey, slot *assemblySlot) {
	if current := r.slots[key]; current != slot {
		return
	}
	delete(r.slots, key)
	for i, candidate := range r.order {
		if candidate == key {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
	reserved := slot.reserved
	slot.reserved = 0
	r.budget.release(reserved)
}
