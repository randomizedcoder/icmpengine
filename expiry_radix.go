package icmpengine

// radixExpiry is a most-significant-digit radix trie over the 64-bit key
// uint64(expiry.UnixNano()) ^ (1<<63). The XOR bias maps signed-time order onto
// unsigned MSD order (correct for any epoch). With 8-bit digits there are 8
// levels; because the levels consume the full 64 bits, every distinct key has
// its own leaf, so a leaf bucket only ever holds entries with an IDENTICAL key —
// which is what makes peek exact. An occupancy bitmap per node finds the
// lowest-digit child in O(1), so all operations are O(8) ≈ constant, independent
// of n. It keeps its own addr->seq index and ignores pending.index.
//
// This is deliberately NOT a Dijkstra/monotone radix heap: that structure
// requires "no key below the last-extracted min", which this workload violates
// (arbitrary removal and non-monotone inserts). A fixed-base trie has no such
// precondition.

import (
	"math/bits"
	"net/netip"
)

const (
	radixBits   = 8
	radixDigits = 64 / radixBits // 8 levels
	radixWords  = (1 << radixBits) / 64
)

type rentry struct {
	p          *pending
	prev, next *rentry
	leaf       *rnode
}

type rnode struct {
	occ    [radixWords]uint64
	child  map[uint8]*rnode // nil on leaves (level == radixDigits)
	count  int              // entries in this subtree
	parent *rnode
	digit  uint8
	level  int
	head   *rentry // leaf only: list of identical-key entries
	tail   *rentry
}

type radixExpiry struct {
	root  *rnode
	index map[netip.Addr]map[sequence]*rentry
}

func newRadixExpiry() *radixExpiry {
	return &radixExpiry{
		root:  &rnode{child: make(map[uint8]*rnode)},
		index: make(map[netip.Addr]map[sequence]*rentry),
	}
}

func radixKey(p *pending) uint64 { return uint64(p.expiry.UnixNano()) ^ (1 << 63) }

func radixDigit(k uint64, level int) uint8 {
	return uint8(k >> (radixBits * (radixDigits - 1 - level)))
}

func setOcc(occ *[radixWords]uint64, d uint8)   { occ[d>>6] |= 1 << (d & 63) }
func clearOcc(occ *[radixWords]uint64, d uint8) { occ[d>>6] &^= 1 << (d & 63) }

func lowestOcc(occ *[radixWords]uint64) uint8 {
	for w := 0; w < radixWords; w++ {
		if occ[w] != 0 {
			return uint8(w*64 + bits.TrailingZeros64(occ[w]))
		}
	}
	return 0 // unreachable while count > 0
}

func (q *radixExpiry) insert(p *pending) *rentry {
	k := radixKey(p)
	node := q.root
	node.count++
	for lvl := 0; lvl < radixDigits; lvl++ {
		d := radixDigit(k, lvl)
		setOcc(&node.occ, d)
		child := node.child[d]
		if child == nil {
			child = &rnode{parent: node, digit: d, level: lvl + 1}
			if lvl+1 < radixDigits {
				child.child = make(map[uint8]*rnode)
			}
			node.child[d] = child
		}
		node = child
		node.count++
	}
	e := &rentry{p: p, leaf: node}
	if node.tail == nil {
		node.head, node.tail = e, e
	} else {
		node.tail.next = e
		e.prev = node.tail
		node.tail = e
	}
	return e
}

func (q *radixExpiry) removeEntry(e *rentry) {
	leaf := e.leaf
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		leaf.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		leaf.tail = e.prev
	}
	e.prev, e.next = nil, nil

	for node := leaf; node != nil; {
		node.count--
		parent := node.parent
		if node.count == 0 && parent != nil {
			clearOcc(&parent.occ, node.digit)
			delete(parent.child, node.digit)
			node.parent = nil
		}
		node = parent
	}
}

func (q *radixExpiry) push(p *pending) {
	m, ok := q.index[p.addr]
	if !ok {
		m = make(map[sequence]*rentry)
		q.index[p.addr] = m
	} else if old, ok := m[p.seq]; ok {
		q.removeEntry(old)
	}
	m[p.seq] = q.insert(p)
}

func (q *radixExpiry) peek() (*pending, bool) {
	if q.root.count == 0 {
		return nil, false
	}
	node := q.root
	for node.level < radixDigits {
		node = node.child[lowestOcc(&node.occ)]
	}
	return node.head.p, true
}

func (q *radixExpiry) remove(addr netip.Addr, seq sequence) (*pending, bool) {
	m, ok := q.index[addr]
	if !ok {
		return nil, false
	}
	e, ok := m[seq]
	if !ok {
		return nil, false
	}
	q.removeEntry(e)
	delete(m, seq)
	if len(m) == 0 {
		delete(q.index, addr)
	}
	return e.p, true
}

func (q *radixExpiry) deleteAddr(addr netip.Addr) {
	m, ok := q.index[addr]
	if !ok {
		return
	}
	for seq, e := range m {
		q.removeEntry(e)
		delete(m, seq)
	}
	delete(q.index, addr)
}

func (q *radixExpiry) len() int { return q.root.count }
