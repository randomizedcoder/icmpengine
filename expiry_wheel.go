package icmpengine

// wheelExpiry is a hierarchical, absolute-time timing wheel. Four levels of
// increasing granularity (µs / ms / s / 1000s, 1024 slots each) bucket entries
// by absolute expiry relative to a base fixed at the first push; each slot is a
// list kept sorted by expiry so the slot head is that slot's min. An occupancy
// bitmap per level finds the earliest non-empty slot in O(1). Keys below base or
// past the coarsest level spill into an exact-ordered google/btree overflow, and
// peek returns min(earliest wheel entry, overflow.Min()).
//
// Honest limitation: because base is fixed (there is no external "now" tick in
// this abstraction), a wide spread of timeouts inserted min-last pushes much of
// the working set into the overflow btree, so under heterogeneous timeouts the
// wheel degrades toward btree performance. It is at its best under near-monotonic
// (uniform-timeout) load. It keeps its own addr->seq index and ignores pending.index.

import (
	"math/bits"
	"net/netip"
	"time"

	"github.com/google/btree"
)

const (
	wheelLevels = 4
	wheelSlots  = 1024
	wheelWords  = wheelSlots / 64 // 16
)

var wheelGran = [wheelLevels]int64{
	int64(time.Microsecond),
	int64(time.Millisecond),
	int64(time.Second),
	int64(1000 * time.Second),
}

type wnode struct {
	p          *pending
	prev, next *wnode
	lvl        int // -1 == overflow (stored in the btree, not a slot)
	slot       int
}

type wheelLevel struct {
	slot [wheelSlots]*wnode // head of the per-slot sorted list
	occ  [wheelWords]uint64
}

func (l *wheelLevel) insert(idx int, node *wnode) {
	head := l.slot[idx]
	if head == nil || !head.p.expiry.Before(node.p.expiry) {
		node.next = head
		if head != nil {
			head.prev = node
		}
		l.slot[idx] = node
	} else {
		cur := head
		for cur.next != nil && cur.next.p.expiry.Before(node.p.expiry) {
			cur = cur.next
		}
		node.next = cur.next
		if cur.next != nil {
			cur.next.prev = node
		}
		cur.next = node
		node.prev = cur
	}
	l.occ[idx>>6] |= 1 << (uint(idx) & 63)
}

func (l *wheelLevel) unlink(idx int, node *wnode) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		l.slot[idx] = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	}
	node.prev, node.next = nil, nil
	if l.slot[idx] == nil {
		l.occ[idx>>6] &^= 1 << (uint(idx) & 63)
	}
}

func (l *wheelLevel) earliest() (*wnode, bool) {
	for w := 0; w < wheelWords; w++ {
		if l.occ[w] != 0 {
			return l.slot[w*64+bits.TrailingZeros64(l.occ[w])], true
		}
	}
	return nil, false
}

type wheelExpiry struct {
	base     int64
	hasBase  bool
	span     [wheelLevels]int64
	lvls     [wheelLevels]wheelLevel
	overflow *btree.BTreeG[*pending]
	n        int
	index    map[netip.Addr]map[sequence]*wnode
}

func newWheelExpiry() *wheelExpiry {
	q := &wheelExpiry{
		overflow: btree.NewG[*pending](btreeDegree, lessPending),
		index:    make(map[netip.Addr]map[sequence]*wnode),
	}
	for i := 0; i < wheelLevels; i++ {
		q.span[i] = wheelSlots * wheelGran[i]
	}
	return q
}

// locate returns the level and slot for key k, or over=true for the overflow btree.
func (q *wheelExpiry) locate(k int64) (lvl, slot int, over bool) {
	if k < q.base {
		return 0, 0, true
	}
	off := k - q.base
	for i := 0; i < wheelLevels; i++ {
		if off < q.span[i] {
			return i, int(off / wheelGran[i]), false
		}
		off -= q.span[i]
	}
	return 0, 0, true
}

func (q *wheelExpiry) removeNode(node *wnode) {
	if node.lvl == -1 {
		q.overflow.Delete(node.p)
	} else {
		q.lvls[node.lvl].unlink(node.slot, node)
	}
}

func (q *wheelExpiry) push(p *pending) {
	m, ok := q.index[p.addr]
	if !ok {
		m = make(map[sequence]*wnode)
		q.index[p.addr] = m
	} else if old, ok := m[p.seq]; ok {
		q.removeNode(old)
		q.n--
	}
	if !q.hasBase {
		q.base = p.expiry.UnixNano()
		q.hasBase = true
	}
	node := &wnode{p: p}
	lvl, slot, over := q.locate(p.expiry.UnixNano())
	if over {
		node.lvl = -1
		q.overflow.ReplaceOrInsert(p)
	} else {
		node.lvl, node.slot = lvl, slot
		q.lvls[lvl].insert(slot, node)
	}
	m[p.seq] = node
	q.n++
}

func (q *wheelExpiry) peek() (*pending, bool) {
	var wheelMin *pending
	for i := 0; i < wheelLevels; i++ {
		if node, ok := q.lvls[i].earliest(); ok {
			wheelMin = node.p
			break
		}
	}
	overMin, ok := q.overflow.Min()
	switch {
	case wheelMin == nil && !ok:
		return nil, false
	case wheelMin == nil:
		return overMin, true
	case !ok:
		return wheelMin, true
	case overMin.expiry.Before(wheelMin.expiry):
		return overMin, true
	default:
		return wheelMin, true
	}
}

func (q *wheelExpiry) remove(addr netip.Addr, seq sequence) (*pending, bool) {
	m, ok := q.index[addr]
	if !ok {
		return nil, false
	}
	node, ok := m[seq]
	if !ok {
		return nil, false
	}
	q.removeNode(node)
	q.n--
	delete(m, seq)
	if len(m) == 0 {
		delete(q.index, addr)
	}
	return node.p, true
}

func (q *wheelExpiry) deleteAddr(addr netip.Addr) {
	m, ok := q.index[addr]
	if !ok {
		return
	}
	for seq, node := range m {
		q.removeNode(node)
		q.n--
		delete(m, seq)
	}
	delete(q.index, addr)
}

func (q *wheelExpiry) len() int { return q.n }
