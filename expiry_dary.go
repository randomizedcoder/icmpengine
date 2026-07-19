package icmpengine

// daryExpiry is an array-backed d-ary min-heap keyed by expiry. A higher fan-out
// than the binary heap makes the tree shallower, so sift-down touches fewer,
// more cache-local nodes at the cost of scanning up to d children per step. It
// reuses pending.index (the array position) and an addr->seq index for O(1)
// lookup / O(log_d n) removal. Peek is O(1).

import "net/netip"

type daryExpiry struct {
	d     int
	h     []*pending
	index map[netip.Addr]map[sequence]*pending
}

func newDaryExpiry(d int) *daryExpiry {
	if d < 2 {
		d = 2
	}
	return &daryExpiry{d: d, index: make(map[netip.Addr]map[sequence]*pending)}
}

func (q *daryExpiry) less(i, j int) bool { return q.h[i].expiry.Before(q.h[j].expiry) }

func (q *daryExpiry) swap(i, j int) {
	q.h[i], q.h[j] = q.h[j], q.h[i]
	q.h[i].index = i
	q.h[j].index = j
}

func (q *daryExpiry) up(i int) {
	for i > 0 {
		parent := (i - 1) / q.d
		if !q.less(i, parent) {
			break
		}
		q.swap(i, parent)
		i = parent
	}
}

func (q *daryExpiry) down(i int) {
	n := len(q.h)
	for {
		first := q.d*i + 1
		if first >= n {
			break
		}
		smallest := first
		for k := 1; k < q.d; k++ {
			c := first + k
			if c >= n {
				break
			}
			if q.less(c, smallest) {
				smallest = c
			}
		}
		if !q.less(smallest, i) {
			break
		}
		q.swap(i, smallest)
		i = smallest
	}
}

func (q *daryExpiry) removeAt(i int) {
	n := len(q.h) - 1
	if n != i {
		q.swap(i, n)
	}
	q.h[n].index = -1
	q.h[n] = nil
	q.h = q.h[:n]
	if i < n {
		q.down(i)
		q.up(i)
	}
}

func (q *daryExpiry) push(p *pending) {
	if m, ok := q.index[p.addr]; ok {
		if old, ok := m[p.seq]; ok {
			q.removeAt(old.index)
		}
	} else {
		q.index[p.addr] = make(map[sequence]*pending)
	}
	q.index[p.addr][p.seq] = p
	p.index = len(q.h)
	q.h = append(q.h, p)
	q.up(p.index)
}

func (q *daryExpiry) peek() (*pending, bool) {
	if len(q.h) == 0 {
		return nil, false
	}
	return q.h[0], true
}

func (q *daryExpiry) remove(addr netip.Addr, seq sequence) (*pending, bool) {
	m, ok := q.index[addr]
	if !ok {
		return nil, false
	}
	p, ok := m[seq]
	if !ok {
		return nil, false
	}
	q.removeAt(p.index)
	delete(m, seq)
	if len(m) == 0 {
		delete(q.index, addr)
	}
	return p, true
}

func (q *daryExpiry) deleteAddr(addr netip.Addr) {
	m, ok := q.index[addr]
	if !ok {
		return
	}
	for seq, p := range m {
		q.removeAt(p.index)
		delete(m, seq)
	}
	delete(q.index, addr)
}

func (q *daryExpiry) len() int { return len(q.h) }
