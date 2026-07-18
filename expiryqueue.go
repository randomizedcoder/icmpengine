package icmpengine

// expiryQueue tracks outstanding pings ordered by their expiry time.
//
// It replaces the older container/list doubly-linked-list plus a
// map[netip.Addr]map[Sequence]*list.Element. Using container/heap gives an
// O(log n) push/pop keyed by the true soonest expiry (rather than relying on
// insertion order equalling expiry order, which only held while every ping used
// an identical timeout), and the typed index map removes the list.Element.Value
// type assertions that used to be sprinkled through the receiver and expirer.
//
// expiryQueue is NOT safe for concurrent use; the Engine serializes all access
// under its single mutex.

import (
	"container/heap"
	"net/netip"
	"time"
)

// pending is one outstanding ICMP echo request awaiting a reply or timeout.
type pending struct {
	addr     netip.Addr
	seq      sequence
	send     time.Time
	expiry   time.Time
	fakeDrop bool
	index    int // maintained by heap.Interface; -1 once removed
}

// expiryHeap is a min-heap of *pending ordered by expiry time. It implements
// heap.Interface and is only manipulated through the container/heap functions.
type expiryHeap []*pending

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].expiry.Before(h[j].expiry) }

func (h expiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *expiryHeap) Push(x any) {
	p := x.(*pending)
	p.index = len(*h)
	*h = append(*h, p)
}

func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old)
	p := old[n-1]
	old[n-1] = nil // avoid retaining the pointer
	p.index = -1
	*h = old[:n-1]
	return p
}

// expiryQueue wraps the heap with an index for O(1) lookup/removal by (addr,seq).
type expiryQueue struct {
	h     expiryHeap
	index map[netip.Addr]map[sequence]*pending
}

func newExpiryQueue() *expiryQueue {
	return &expiryQueue{
		index: make(map[netip.Addr]map[sequence]*pending),
	}
}

// push adds p to the queue. A duplicate (addr,seq) overwrites the previous entry.
func (q *expiryQueue) push(p *pending) {
	if m, ok := q.index[p.addr]; ok {
		if old, ok := m[p.seq]; ok {
			heap.Remove(&q.h, old.index)
		}
	} else {
		q.index[p.addr] = make(map[sequence]*pending)
	}
	q.index[p.addr][p.seq] = p
	heap.Push(&q.h, p)
}

// peek returns the entry with the soonest expiry without removing it.
func (q *expiryQueue) peek() (*pending, bool) {
	if len(q.h) == 0 {
		return nil, false
	}
	return q.h[0], true
}

// remove deletes and returns the entry for (addr,seq) if present.
func (q *expiryQueue) remove(addr netip.Addr, seq sequence) (*pending, bool) {
	m, ok := q.index[addr]
	if !ok {
		return nil, false
	}
	p, ok := m[seq]
	if !ok {
		return nil, false
	}
	heap.Remove(&q.h, p.index)
	delete(m, seq)
	if len(m) == 0 {
		delete(q.index, addr)
	}
	return p, true
}

// deleteAddr removes every outstanding entry for addr. Used when a Ping returns
// so no stale entries linger for a destination that is no longer being pinged.
func (q *expiryQueue) deleteAddr(addr netip.Addr) {
	m, ok := q.index[addr]
	if !ok {
		return
	}
	for seq, p := range m {
		heap.Remove(&q.h, p.index)
		delete(m, seq)
	}
	delete(q.index, addr)
}

// len reports the number of outstanding entries.
func (q *expiryQueue) len() int { return len(q.h) }
