package icmpengine

import (
	"container/list"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// listExpiry is a container/list baseline used only for benchmarking — it is
// never compiled into the shipping library. Front == soonest expiry holds ONLY
// when pushes arrive in non-decreasing expiry order (PushBack keeps it sorted),
// which the benchmark guarantees and the engine's single fixed timeout also
// satisfies. The heap and btree backends have no such constraint, which is why
// this stays a baseline rather than a runtime backend.
type listExpiry struct {
	l     *list.List
	index map[netip.Addr]map[sequence]*list.Element
}

func newListExpiry() *listExpiry {
	return &listExpiry{
		l:     list.New(),
		index: make(map[netip.Addr]map[sequence]*list.Element),
	}
}

func (t *listExpiry) push(p *pending) {
	if m, ok := t.index[p.addr]; ok {
		if old, ok := m[p.seq]; ok {
			t.l.Remove(old)
		}
	} else {
		t.index[p.addr] = make(map[sequence]*list.Element)
	}
	t.index[p.addr][p.seq] = t.l.PushBack(p)
}

func (t *listExpiry) peek() (*pending, bool) {
	f := t.l.Front()
	if f == nil {
		return nil, false
	}
	return f.Value.(*pending), true
}

func (t *listExpiry) remove(addr netip.Addr, seq sequence) (*pending, bool) {
	m, ok := t.index[addr]
	if !ok {
		return nil, false
	}
	el, ok := m[seq]
	if !ok {
		return nil, false
	}
	p := el.Value.(*pending)
	t.l.Remove(el)
	delete(m, seq)
	if len(m) == 0 {
		delete(t.index, addr)
	}
	return p, true
}

func (t *listExpiry) deleteAddr(addr netip.Addr) {
	m, ok := t.index[addr]
	if !ok {
		return
	}
	for seq, el := range m {
		t.l.Remove(el)
		delete(m, seq)
	}
	delete(t.index, addr)
}

func (t *listExpiry) len() int { return t.l.Len() }

// benchBackends is the set compared by BenchmarkTracker: the two runtime
// backends plus the list baseline.
var benchBackends = []struct {
	name string
	make func() expiryTracker
}{
	{"heap", func() expiryTracker { return newHeapExpiry() }},
	{"btree", func() expiryTracker { return newBTreeExpiry() }},
	{"list", func() expiryTracker { return newListExpiry() }},
}

func makeBenchAddrs(n int) []netip.Addr {
	addrs := make([]netip.Addr, n)
	for i := range addrs {
		addrs[i] = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	}
	return addrs
}

// BenchmarkTracker models steady-state expiry churn: N outstanding pings (one
// per address), then per iteration remove one by (addr,seq), push a replacement
// with a later expiry, and peek the soonest — the exact mix the receiver and
// expirer drive on every packet.
func BenchmarkTracker(b *testing.B) {
	sizes := []int{1, 10, 100, 1000, 10000}
	base := time.Unix(1_700_000_000, 0)

	for _, bk := range benchBackends {
		for _, n := range sizes {
			b.Run(fmt.Sprintf("%s/N=%d", bk.name, n), func(b *testing.B) {
				addrs := makeBenchAddrs(n)
				seqs := make([]sequence, n)
				q := bk.make()

				var tick int64
				for i := 0; i < n; i++ {
					q.push(&pending{addr: addrs[i], send: base, expiry: base.Add(time.Duration(tick) * time.Millisecond)})
					tick++
				}

				b.ReportAllocs()
				i := 0
				for b.Loop() {
					idx := i % n
					q.remove(addrs[idx], seqs[idx])
					seqs[idx]++
					q.push(&pending{addr: addrs[idx], seq: seqs[idx], send: base, expiry: base.Add(time.Duration(tick) * time.Millisecond)})
					tick++
					q.peek()
					i++
				}
			})
		}
	}
}
