package icmpengine

// pairingExpiry is a pairing heap: a multiway tree where every node's expiry is
// <= its children's. peek (the root) and push (one meld) are O(1); removal melds
// the affected node's children back in, amortized O(log n). Arbitrary removal
// uses child/sibling/prev back-pointers to cut a node in O(1) before re-melding.
// It keeps its own addr->seq index and ignores pending.index.

import "net/netip"

type pnode struct {
	p                    *pending
	child, sibling, prev *pnode // prev = parent (if leftmost child) or left sibling
}

type pairingExpiry struct {
	root    *pnode
	n       int
	index   map[netip.Addr]map[sequence]*pnode
	scratch []*pnode // reused by mergePairs to avoid per-removal allocation
}

func newPairingExpiry() *pairingExpiry {
	return &pairingExpiry{index: make(map[netip.Addr]map[sequence]*pnode)}
}

// pmeld makes the larger-expiry root a child of the smaller and returns the winner.
func pmeld(a, b *pnode) *pnode {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	if b.p.expiry.Before(a.p.expiry) {
		a, b = b, a
	}
	b.prev = a
	b.sibling = a.child
	if a.child != nil {
		a.child.prev = b
	}
	a.child = b
	return a
}

// mergePairs combines a sibling list into one heap using the classic two-pass
// method, iteratively (bounded child lists can be long, so no recursion).
func (q *pairingExpiry) mergePairs(first *pnode) *pnode {
	if first == nil {
		return nil
	}
	q.scratch = q.scratch[:0]
	for n := first; n != nil; {
		a := n
		b := a.sibling
		var next *pnode
		if b != nil {
			next = b.sibling
			b.sibling, b.prev = nil, nil
		}
		a.sibling, a.prev = nil, nil
		q.scratch = append(q.scratch, pmeld(a, b))
		n = next
	}
	res := q.scratch[len(q.scratch)-1]
	for i := len(q.scratch) - 2; i >= 0; i-- {
		res = pmeld(q.scratch[i], res)
	}
	return res
}

func (q *pairingExpiry) detach(node *pnode) {
	if node.prev == nil {
		return // root
	}
	if node.prev.child == node {
		node.prev.child = node.sibling
	} else {
		node.prev.sibling = node.sibling
	}
	if node.sibling != nil {
		node.sibling.prev = node.prev
	}
	node.prev, node.sibling = nil, nil
}

func (q *pairingExpiry) deleteNode(node *pnode) {
	if node == q.root {
		q.root = q.mergePairs(node.child)
	} else {
		q.detach(node)
		q.root = pmeld(q.root, q.mergePairs(node.child))
	}
	node.child = nil
	if q.root != nil {
		q.root.prev, q.root.sibling = nil, nil
	}
}

func (q *pairingExpiry) push(p *pending) {
	m, ok := q.index[p.addr]
	if !ok {
		m = make(map[sequence]*pnode)
		q.index[p.addr] = m
	} else if old, ok := m[p.seq]; ok {
		q.deleteNode(old)
		q.n--
	}
	node := &pnode{p: p}
	m[p.seq] = node
	q.root = pmeld(q.root, node)
	q.root.prev, q.root.sibling = nil, nil
	q.n++
}

func (q *pairingExpiry) peek() (*pending, bool) {
	if q.root == nil {
		return nil, false
	}
	return q.root.p, true
}

func (q *pairingExpiry) remove(addr netip.Addr, seq sequence) (*pending, bool) {
	m, ok := q.index[addr]
	if !ok {
		return nil, false
	}
	node, ok := m[seq]
	if !ok {
		return nil, false
	}
	q.deleteNode(node)
	q.n--
	delete(m, seq)
	if len(m) == 0 {
		delete(q.index, addr)
	}
	return node.p, true
}

func (q *pairingExpiry) deleteAddr(addr netip.Addr) {
	m, ok := q.index[addr]
	if !ok {
		return
	}
	for seq, node := range m {
		q.deleteNode(node)
		q.n--
		delete(m, seq)
	}
	delete(q.index, addr)
}

func (q *pairingExpiry) len() int { return q.n }
