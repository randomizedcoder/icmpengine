package icmpengine

import "testing"

// These benchmarks compare case/switch dispatch against function-table dispatch
// (slice- and map-of-funcs) for the two shapes the codebase actually uses:
//   - integer dispatch on Backend (a dense iota) — e.g. newExpiryTracker;
//   - string dispatch — e.g. the CLI's parseBackend/parseLevel.
// The handlers are //go:noinline so each is a real indirect call, isolating the
// dispatch cost from the work. sink defeats dead-code elimination.
//
// Why this exists: as more expiry backends are added, it is worth knowing whether
// the switch statements should become dispatch tables. The measured answer (on the
// dev machine, ns/op):
//
//	integer (Backend): switch 6.5  slice 6.4  map 6.7
//	string           : switch 6.2             map 12.1
//
// A dense-integer switch (Backend, iota 0..N) compiles to a jump table — O(1), the
// same as slice indexing, and it does NOT degrade as cases grow; a map is slower.
// A string switch beats a map until there are many more cases. So keep the
// switches: converting these would be a wash or a regression, and they are cold
// paths anyway (the per-packet hot path already dispatches through the
// expiryTracker interface). Revisit only if a STRING switch grows to dozens of
// cases — that is where a map[string] starts to win. Re-run:
//
//	go test -run '^$' -bench='BenchmarkBackendDispatch|BenchmarkStringDispatch' -benchmem

var sink int

//go:noinline
func dh0() int { return 10 }

//go:noinline
func dh1() int { return 11 }

//go:noinline
func dh2() int { return 12 }

//go:noinline
func dh3() int { return 13 }

//go:noinline
func dh4() int { return 14 }

//go:noinline
func dh5() int { return 15 }

func backendSwitch(b Backend) int {
	switch b {
	case BackendHeap:
		return dh0()
	case BackendBTree:
		return dh1()
	case BackendDaryHeap:
		return dh2()
	case BackendRadix:
		return dh3()
	case BackendPairing:
		return dh4()
	case BackendTimingWheel:
		return dh5()
	}
	return -1
}

var backendSlice = [...]func() int{
	BackendHeap:        dh0,
	BackendBTree:       dh1,
	BackendDaryHeap:    dh2,
	BackendRadix:       dh3,
	BackendPairing:     dh4,
	BackendTimingWheel: dh5,
}

var backendMap = map[Backend]func() int{
	BackendHeap:        dh0,
	BackendBTree:       dh1,
	BackendDaryHeap:    dh2,
	BackendRadix:       dh3,
	BackendPairing:     dh4,
	BackendTimingWheel: dh5,
}

// BenchmarkBackendDispatch: integer (dense iota) dispatch, 6-way.
func BenchmarkBackendDispatch(b *testing.B) {
	all := []Backend{BackendHeap, BackendBTree, BackendDaryHeap, BackendRadix, BackendPairing, BackendTimingWheel}
	b.Run("switch", func(b *testing.B) {
		s, i := 0, 0
		for b.Loop() {
			s += backendSwitch(all[i%len(all)])
			i++
		}
		sink = s
	})
	b.Run("slice", func(b *testing.B) {
		s, i := 0, 0
		for b.Loop() {
			s += backendSlice[all[i%len(all)]]()
			i++
		}
		sink = s
	})
	b.Run("map", func(b *testing.B) {
		s, i := 0, 0
		for b.Loop() {
			s += backendMap[all[i%len(all)]]()
			i++
		}
		sink = s
	})
}

// Backend names, named once so goconst is happy and the switch/map/keys agree.
const (
	kHeap    = "heap"
	kBTree   = "btree"
	kDary    = "dary"
	kRadix   = "radix"
	kPairing = "pairing"
	kWheel   = "wheel"
)

func stringSwitch(s string) int {
	switch s {
	case kHeap:
		return 0
	case kBTree:
		return 1
	case kDary:
		return 2
	case kRadix:
		return 3
	case kPairing:
		return 4
	case kWheel:
		return 5
	}
	return -1
}

var stringMap = map[string]int{
	kHeap: 0, kBTree: 1, kDary: 2, kRadix: 3, kPairing: 4, kWheel: 5,
}

// BenchmarkStringDispatch: string dispatch, 6-way.
func BenchmarkStringDispatch(b *testing.B) {
	keys := []string{kHeap, kBTree, kDary, kRadix, kPairing, kWheel}
	b.Run("switch", func(b *testing.B) {
		s, i := 0, 0
		for b.Loop() {
			s += stringSwitch(keys[i%len(keys)])
			i++
		}
		sink = s
	})
	b.Run("map", func(b *testing.B) {
		s, i := 0, 0
		for b.Loop() {
			s += stringMap[keys[i%len(keys)]]
			i++
		}
		sink = s
	})
}
