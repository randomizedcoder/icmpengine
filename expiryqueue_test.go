package icmpengine

import (
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

// TestExpiryQueuePeekOrder verifies peek always returns the soonest expiry,
// regardless of insertion order.
func TestExpiryQueuePeekOrder(t *testing.T) {
	q := newExpiryQueue()
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
		t.Fatal("peek on empty queue returned ok=true")
	}
}

// TestExpiryQueueRemoveMiddle removes an interior element and checks ordering holds.
func TestExpiryQueueRemoveMiddle(t *testing.T) {
	q := newExpiryQueue()
	base := time.Unix(1_700_000_000, 0)
	ip := mustAddr("::1")

	for i := sequence(0); i < 5; i++ {
		q.push(newPending(ip, i, base.Add(time.Duration(i)*time.Millisecond)))
	}

	// Remove seq 2 (interior).
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
}

// TestExpiryQueueDeleteAddr removes all of one address without touching another.
func TestExpiryQueueDeleteAddr(t *testing.T) {
	q := newExpiryQueue()
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
}

// TestExpiryQueuePushDuplicate verifies a re-pushed (addr,seq) overwrites cleanly.
func TestExpiryQueuePushDuplicate(t *testing.T) {
	q := newExpiryQueue()
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
}
