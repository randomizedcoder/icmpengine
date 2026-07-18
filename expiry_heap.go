package icmpengine

// heapExpiry is the default expiryTracker: a container/heap min-heap keyed by
// expiry time, plus an addr->seq->*pending index for O(1) lookup and O(log n)
// removal by (addr, seq). Peek is O(1). It carries no external dependency.

import (
	"container/heap"
	"net/netip"
)

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

// heapExpiry wraps the heap with an index for O(1) lookup/removal by (addr,seq).
type heapExpiry struct {
	h     expiryHeap
	index map[netip.Addr]map[sequence]*pending
}

func newHeapExpiry() *heapExpiry {
	return &heapExpiry{
		index: make(map[netip.Addr]map[sequence]*pending),
	}
}

func (q *heapExpiry) push(p *pending) {
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

func (q *heapExpiry) peek() (*pending, bool) {
	if len(q.h) == 0 {
		return nil, false
	}
	return q.h[0], true
}

func (q *heapExpiry) remove(addr netip.Addr, seq sequence) (*pending, bool) {
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

func (q *heapExpiry) deleteAddr(addr netip.Addr) {
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

func (q *heapExpiry) len() int { return len(q.h) }
