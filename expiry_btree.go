package icmpengine

// btreeExpiry is an expiryTracker backed by github.com/google/btree (generic).
// The tree orders whole *pending items by (expiry, addr, seq); an addr->seq
// index recovers the item so remove/deleteAddr can Delete it (btree's Delete
// needs an item that compares equal, i.e. the full key). All operations are
// O(log n). Like the other backends it is not safe for concurrent use.

import (
	"net/netip"

	"github.com/google/btree"
)

// btreeDegree controls node fan-out (max 2*degree-1 items/node). 16 is a
// reasonable default for this workload; it is cheap to revisit via BenchmarkTracker.
const btreeDegree = 16

// lessPending is a strict total order over pending: by expiry, then address,
// then sequence. A total order (not just by expiry) is required because the
// btree distinguishes items solely through this function.
func lessPending(a, b *pending) bool {
	if !a.expiry.Equal(b.expiry) {
		return a.expiry.Before(b.expiry)
	}
	if a.addr != b.addr {
		return a.addr.Less(b.addr)
	}
	return a.seq < b.seq
}

type btreeExpiry struct {
	tree  *btree.BTreeG[*pending]
	index map[netip.Addr]map[sequence]*pending
}

func newBTreeExpiry() *btreeExpiry {
	return &btreeExpiry{
		tree:  btree.NewG[*pending](btreeDegree, lessPending),
		index: make(map[netip.Addr]map[sequence]*pending),
	}
}

func (t *btreeExpiry) push(p *pending) {
	if m, ok := t.index[p.addr]; ok {
		if old, ok := m[p.seq]; ok {
			t.tree.Delete(old)
		}
	} else {
		t.index[p.addr] = make(map[sequence]*pending)
	}
	t.index[p.addr][p.seq] = p
	t.tree.ReplaceOrInsert(p)
}

func (t *btreeExpiry) peek() (*pending, bool) {
	return t.tree.Min()
}

func (t *btreeExpiry) remove(addr netip.Addr, seq sequence) (*pending, bool) {
	m, ok := t.index[addr]
	if !ok {
		return nil, false
	}
	p, ok := m[seq]
	if !ok {
		return nil, false
	}
	t.tree.Delete(p)
	delete(m, seq)
	if len(m) == 0 {
		delete(t.index, addr)
	}
	return p, true
}

func (t *btreeExpiry) deleteAddr(addr netip.Addr) {
	m, ok := t.index[addr]
	if !ok {
		return
	}
	for seq, p := range m {
		t.tree.Delete(p)
		delete(m, seq)
	}
	delete(t.index, addr)
}

func (t *btreeExpiry) len() int { return t.tree.Len() }
