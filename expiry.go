package icmpengine

// This file defines the expiry-tracking abstraction. The engine tracks every
// outstanding ping so the expirer can find the soonest-to-expire one and the
// receiver can remove one by (addr, seq) when a reply arrives. That is a
// priority-queue-with-arbitrary-removal, and several data structures can serve
// it. expiryTracker is the seam that lets us swap and benchmark them.

import (
	"net/netip"
	"time"
)

// pending is one outstanding ICMP echo request awaiting a reply or timeout.
// The index field is used only by the container/heap backend (heapExpiry); the
// other backends ignore it.
type pending struct {
	addr     netip.Addr
	seq      sequence
	send     time.Time
	expiry   time.Time
	fakeDrop bool
	index    int // heap-only: position in the heap, -1 once removed
}

// expiryTracker stores outstanding pings ordered by expiry time. Implementations
// are NOT required to be safe for concurrent use: the Engine serializes every
// call under its single mutex.
type expiryTracker interface {
	// push inserts p. A duplicate (addr, seq) overwrites the previous entry.
	push(p *pending)
	// peek returns the entry with the soonest expiry without removing it.
	peek() (*pending, bool)
	// remove deletes and returns the entry for (addr, seq) if present.
	remove(addr netip.Addr, seq sequence) (*pending, bool)
	// deleteAddr removes every outstanding entry for addr.
	deleteAddr(addr netip.Addr)
	// len reports the number of outstanding entries.
	len() int
}

// Backend selects the expiry-tracking data structure used by an Engine.
type Backend int

const (
	// BackendHeap uses container/heap (the default). Peek is O(1); push and
	// remove are O(log n). No external dependency.
	BackendHeap Backend = iota
	// BackendBTree uses github.com/google/btree. All operations are O(log n).
	BackendBTree
	// BackendDaryHeap uses an 8-ary array heap — shallower than the binary heap,
	// which benchmarks faster on this remove-heavy workload (see BenchmarkDaryFanout).
	BackendDaryHeap
	// BackendRadix uses a fixed-base MSD radix trie over the 64-bit expiry key;
	// all operations are O(64/8)=O(8), independent of n.
	BackendRadix
	// BackendPairing uses a pairing heap (O(1) push/peek).
	BackendPairing
	// BackendTimingWheel uses a hierarchical absolute-time timing wheel with a
	// btree overflow. Best under near-monotonic load; see expiry_wheel.go.
	BackendTimingWheel

	// daryFanout is the fan-out for BackendDaryHeap (8 benchmarks best; see
	// BenchmarkDaryFanout in expiry_bench_test.go).
	daryFanout = 8
)

// String implements fmt.Stringer for nicer logging and flag handling.
func (b Backend) String() string {
	switch b {
	case BackendBTree:
		return "btree"
	case BackendDaryHeap:
		return "dary"
	case BackendRadix:
		return "radix"
	case BackendPairing:
		return "pairing"
	case BackendTimingWheel:
		return "wheel"
	default:
		return "heap"
	}
}

// newExpiryTracker builds the tracker for the selected backend.
func newExpiryTracker(b Backend) expiryTracker {
	switch b {
	case BackendBTree:
		return newBTreeExpiry()
	case BackendDaryHeap:
		return newDaryExpiry(daryFanout)
	case BackendRadix:
		return newRadixExpiry()
	case BackendPairing:
		return newPairingExpiry()
	case BackendTimingWheel:
		return newWheelExpiry()
	default:
		return newHeapExpiry()
	}
}
