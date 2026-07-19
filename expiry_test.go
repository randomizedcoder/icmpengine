package icmpengine

import (
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"
)

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func newPending(addr netip.Addr, seq sequence, expiry time.Time) *pending {
	return &pending{addr: addr, seq: seq, send: expiry.Add(-time.Second), expiry: expiry}
}

// trackerBackends is every runtime-selectable expiry backend. The correctness
// tests below run against all of them so every structure stays in lockstep.
var trackerBackends = []Backend{
	BackendHeap, BackendBTree, BackendDaryHeap, BackendRadix, BackendPairing, BackendTimingWheel,
}

// forEachBackend runs fn against a fresh tracker for every backend, as subtests.
func forEachBackend(t *testing.T, fn func(t *testing.T, q expiryTracker)) {
	t.Helper()
	for _, b := range trackerBackends {
		t.Run(b.String(), func(t *testing.T) { fn(t, newExpiryTracker(b)) })
	}
}

// TestTrackerPeekOrder verifies peek always returns the soonest expiry,
// regardless of insertion order.
func TestTrackerPeekOrder(t *testing.T) {
	forEachBackend(t, func(t *testing.T, q expiryTracker) {
		base := time.Unix(1_700_000_000, 0)
		ip := mustAddr("127.0.0.1")

		// Insert out of expiry order.
		q.push(newPending(ip, 2, base.Add(200*time.Millisecond)))
		q.push(newPending(ip, 0, base.Add(0)))
		q.push(newPending(ip, 1, base.Add(100*time.Millisecond)))

		if q.len() != 3 {
			t.Fatalf("len = %d, want 3", q.len())
		}

		// Peek/remove should yield ascending expiry: seq 0,1,2.
		for want := sequence(0); want < 3; want++ {
			p, ok := q.peek()
			if !ok {
				t.Fatalf("peek returned !ok at want=%d", want)
			}
			if p.seq != want {
				t.Fatalf("peek seq = %d, want %d", p.seq, want)
			}
			got, ok := q.remove(p.addr, p.seq)
			if !ok || got.seq != want {
				t.Fatalf("remove seq = %d ok=%t, want %d", got.seq, ok, want)
			}
		}
		if q.len() != 0 {
			t.Fatalf("len = %d after draining, want 0", q.len())
		}
		if _, ok := q.peek(); ok {
			t.Fatal("peek on empty tracker returned ok=true")
		}
	})
}

// TestTrackerRemoveMiddle removes an interior element and checks ordering holds.
func TestTrackerRemoveMiddle(t *testing.T) {
	forEachBackend(t, func(t *testing.T, q expiryTracker) {
		base := time.Unix(1_700_000_000, 0)
		ip := mustAddr("::1")

		for i := sequence(0); i < 5; i++ {
			q.push(newPending(ip, i, base.Add(time.Duration(i)*time.Millisecond)))
		}

		if _, ok := q.remove(ip, 2); !ok {
			t.Fatal("remove(seq=2) ok=false")
		}
		if _, ok := q.remove(ip, 2); ok {
			t.Fatal("double remove(seq=2) ok=true")
		}

		var got []sequence
		for {
			p, ok := q.peek()
			if !ok {
				break
			}
			got = append(got, p.seq)
			q.remove(p.addr, p.seq)
		}
		want := []sequence{0, 1, 3, 4}
		if len(got) != len(want) {
			t.Fatalf("drained %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("drained %v, want %v", got, want)
			}
		}
	})
}

// TestTrackerDeleteAddr removes all of one address without touching another.
func TestTrackerDeleteAddr(t *testing.T) {
	forEachBackend(t, func(t *testing.T, q expiryTracker) {
		base := time.Unix(1_700_000_000, 0)
		v4 := mustAddr("127.0.0.1")
		v6 := mustAddr("::1")

		for i := sequence(0); i < 3; i++ {
			q.push(newPending(v4, i, base.Add(time.Duration(i)*time.Millisecond)))
			q.push(newPending(v6, i, base.Add(time.Duration(i)*time.Millisecond)))
		}
		if q.len() != 6 {
			t.Fatalf("len = %d, want 6", q.len())
		}

		q.deleteAddr(v4)
		if q.len() != 3 {
			t.Fatalf("len = %d after deleteAddr(v4), want 3", q.len())
		}
		if _, ok := q.remove(v4, 0); ok {
			t.Fatal("v4 entry still present after deleteAddr")
		}
		if _, ok := q.remove(v6, 0); !ok {
			t.Fatal("v6 entry missing after deleteAddr(v4)")
		}

		// deleteAddr on an unknown address is a no-op.
		q.deleteAddr(mustAddr("10.0.0.1"))
	})
}

// TestTrackerDifferential races each backend against a trusted reference heap
// over thousands of random push/remove/deleteAddr operations with heterogeneous
// expiries, asserting that len() and the exact peek() expiry agree at every step.
// This is the real safety net for the intricate radix and wheel backends.
func TestTrackerDifferential(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	type key struct {
		addr netip.Addr
		seq  sequence
	}

	for _, b := range trackerBackends {
		t.Run(b.String(), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(0x1234, 0x5678))
			ref := newHeapExpiry()
			got := newExpiryTracker(b)
			live := make(map[key]bool)
			var liveList []key

			clone := func(p *pending) *pending { c := *p; return &c }
			pruneAddr := func(a netip.Addr) {
				out := liveList[:0]
				for _, k := range liveList {
					if k.addr == a {
						delete(live, k)
					} else {
						out = append(out, k)
					}
				}
				liveList = out
			}

			for i := 0; i < 8000; i++ {
				op := rng.IntN(4)
				if len(liveList) == 0 {
					op = 0 // must push when empty
				}
				switch op {
				case 0, 1: // push (bias toward growth); overwrite if key already live
					addr := netip.AddrFrom4([4]byte{10, 0, byte(rng.IntN(6)), byte(rng.IntN(6))})
					seq := sequence(rng.IntN(12))
					exp := base.Add(time.Duration(rng.Int64N(int64(2 * time.Hour))))
					p := &pending{addr: addr, seq: seq, send: base, expiry: exp}
					ref.push(clone(p))
					got.push(clone(p))
					k := key{addr, seq}
					if !live[k] {
						live[k] = true
						liveList = append(liveList, k)
					}
				case 2: // remove a random live key
					idx := rng.IntN(len(liveList))
					k := liveList[idx]
					ref.remove(k.addr, k.seq)
					got.remove(k.addr, k.seq)
					delete(live, k)
					liveList[idx] = liveList[len(liveList)-1]
					liveList = liveList[:len(liveList)-1]
				case 3: // deleteAddr of a random live addr
					a := liveList[rng.IntN(len(liveList))].addr
					ref.deleteAddr(a)
					got.deleteAddr(a)
					pruneAddr(a)
				}

				if got.len() != ref.len() {
					t.Fatalf("op %d: len = %d, want %d", i, got.len(), ref.len())
				}
				rp, rok := ref.peek()
				gp, gok := got.peek()
				if rok != gok {
					t.Fatalf("op %d: peek ok = %t, want %t (len %d)", i, gok, rok, ref.len())
				}
				if rok && !gp.expiry.Equal(rp.expiry) {
					t.Fatalf("op %d: peek expiry = %s, want %s", i, gp.expiry, rp.expiry)
				}
			}
		})
	}
}

// TestTrackerPushDuplicate verifies a re-pushed (addr,seq) overwrites cleanly.
func TestTrackerPushDuplicate(t *testing.T) {
	forEachBackend(t, func(t *testing.T, q expiryTracker) {
		base := time.Unix(1_700_000_000, 0)
		ip := mustAddr("127.0.0.1")

		q.push(newPending(ip, 7, base.Add(500*time.Millisecond)))
		q.push(newPending(ip, 7, base.Add(10*time.Millisecond))) // overwrite, earlier expiry

		if q.len() != 1 {
			t.Fatalf("len = %d after duplicate push, want 1", q.len())
		}
		p, ok := q.peek()
		if !ok {
			t.Fatal("peek ok=false")
		}
		if p.expiry != base.Add(10*time.Millisecond) {
			t.Fatalf("duplicate push did not overwrite expiry: got %s", p.expiry)
		}
	})
}
