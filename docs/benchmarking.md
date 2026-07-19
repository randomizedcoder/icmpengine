# Expiry-tracker benchmarking

icmpengine tracks every outstanding ping so it can (a) find the soonest one to
time out and (b) remove one the instant its reply arrives. That data structure —
a **priority queue with arbitrary removal** — sits on the hot path of both the
receiver and the expirer, so its performance matters. This note records how the
implementation was chosen.

**TL;DR:** the default is a `container/heap` binary heap (`BackendHeap`). It beat
the alternatives across every workload we measured, and its lead grows with the
number of concurrently-outstanding pings. A `github.com/google/btree` backend is
available via `WithExpiryBackend(BackendBTree)` for anyone whose workload differs.

## The operations

The engine drives these, all under one mutex (so implementations need not be
concurrency-safe):

| op | when | frequency |
|---|---|---|
| `push` | a packet is sent | every packet |
| `remove(addr, seq)` | a reply arrives **or** a timeout fires | every packet |
| `peek()` (soonest expiry) | the expirer picks what to wait for | very frequent |
| `deleteAddr(addr)` | a `Ping` returns | once per Ping |

`N` is the number of pings outstanding at once — roughly the number of
destinations being pinged concurrently, plus any long-timeout pings still
waiting.

## Pluggable backends

The structure lives behind an internal `expiryTracker` interface, so backends can
be swapped and benchmarked without touching the engine. Six ship today, all
runtime-selectable via `WithExpiryBackend` / `-backend` and all validated by the
same correctness suite (including an 8000-op differential fuzz test against a
reference heap):

- **`BackendHeap`** — `container/heap` binary min-heap + an `addr→seq→*pending`
  index for O(1) lookup / O(log n) removal. Peek O(1). No external dependency. **Default.**
- **`BackendDaryHeap`** — an 8-ary array heap (same idea, higher fan-out → shallower,
  more cache-local). O(1) peek, O(log₈ n) push/remove. **Fastest overall** (below).
- **`BackendPairing`** — a pairing heap: O(1) push/peek, amortized-log removal.
- **`BackendBTree`** — `github.com/google/btree`, ordered by `(expiry,addr,seq)`. All ops O(log n).
- **`BackendRadix`** — a fixed-base MSD radix trie over the 64-bit expiry key,
  full-width leaves for exact peek, O(64/8)=O(8) all ops (constant in n).
- **`BackendTimingWheel`** — hierarchical absolute-time buckets + bitmap + a btree
  overflow for out-of-range keys.

The list baseline below (`container/list`) is a benchmark-only structure — O(1)
everything but correct only under monotonic expiry, so not a runtime backend.

A `container/list` baseline is used **in benchmarks only** — it is O(1) for
everything but is only *correct* when expiries are monotonic (see below), so it
is not a runtime backend.

## Why the first comparison was misleading

The engine originally supported only one timeout for all pings. With a single
timeout, every entry's expiry is `send + timeout`, and since send times only
increase, **expiries arrive in insertion order** — a monotonic sequence. That is
the degenerate best case for a heap (and for a plain sorted list, which can just
append). It tells you almost nothing about a structure that has to place inserts
in the *middle* of its order.

Real fleets are the opposite: per-ping timeouts (`PingTimeout`) span a LAN's
10ms and an interplanetary link's hours, so expiries are **heterogeneous** and
inserts land at random positions. The benchmarks below therefore measure two
workloads.

## Workloads

- **uniform** — one timeout for all pings; monotonic expiries. Heap/btree/list.
- **mixed** — heterogeneous expiries drawn µs…hours from a seeded PRNG, a large
  resident "interplanetary" tail that never churns, and out-of-order removals
  (replies arriving off expiry order). Heap/btree. This is the realistic case.
- **engine fleet** — the whole engine (goroutines, channels, timers *and* the
  queue) pinging a fleet under ~20% packet loss, in real time, per backend.

## Results

Numbers below are from the development machine (`-benchmem`, ns per op). Reproduce
on your own hardware with the commands in the next section; the *shape* is what
matters, not the absolute values.

### Tracker micro-benchmark — `mixed` (heterogeneous; the realistic case), ns/op

| N | dary8 | heap | pairing | btree | wheel | radix |
|--:|--:|--:|--:|--:|--:|--:|
| 100 | **487** | 494 | 517 | 769 | 814 | 1493 |
| 1000 | **504** | 540 | 587 | 943 | 871 | 1867 |
| 10000 | **616** | 649 | 667 | 1159 | 1206 | 1742 |
| 100000 | **680** | 732 | 768 | 1906 | 1997 | 2179 |

The **8-ary heap wins at every size** — a shallower array heap is more cache-local
than the binary heap on this remove-heavy churn, at the same 3 allocs/op. The
pairing heap is a close third (one extra alloc for its node). btree and the timing
wheel trail; the radix trie is slowest and allocates far more (its 8-level,
map-per-node trie is O(constant) but with a large constant).

### Tracker micro-benchmark — `uniform` (monotonic; each structure's easy case), ns/op

| N | list | pairing | dary8 | heap | btree | radix | wheel |
|--:|--:|--:|--:|--:|--:|--:|--:|
| 1000 | 465 | 572 | 632 | 630 | 802 | 1943 | 2184 |
| 10000 | 584 | 710 | 797 | 809 | 986 | 1914 | 2302 |

Monotonic expiry is the pairing heap's and the list's best case (O(1) append). The
`list` baseline is fastest but is *incorrect* the moment timeouts differ, so it is
not a runtime backend. Notably the timing wheel is slow even here: its bitmap scans
and pointer-linked slots cost more than a compact array, and its fixed base sends
part of the working set to the btree overflow.

### Engine-level fleet under packet loss (`BenchmarkEngineFleet`), ns/op per PingAll

| targets | dary8 | pairing | heap | btree | wheel | radix |
|--:|--:|--:|--:|--:|--:|--:|
| 100 | 4.09 M | 4.11 M | 4.77 M | 4.33 M | 4.31 M | 4.79 M |
| 1000 | **22.5 M** | 22.9 M | 23.4 M | 26.5 M | 26.9 M | 31.7 M |

End to end most of each packet's cost is goroutine scheduling, channel sends and
timers — but the queue is a real and growing fraction, and the ordering matches the
micro-benchmark: **dary8 fastest**, pairing next, then heap, with btree/wheel/radix
behind. (The 100-target row is noisy at millisecond scale.)

## What wins, and why

- **The 8-ary heap (`BackendDaryHeap`) is the fastest structure** across the mixed
  and engine-level benchmarks, and ties the binary heap on uniform — same algorithm,
  same allocations, just a shallower tree with better cache behavior. It is the
  low-risk "were we overlooking something?" win. (`BackendHeap` remains the default;
  switching is a one-liner.)
- **Pairing heap** is genuinely competitive (best on uniform), at the cost of one
  extra allocation per entry for its node.
- **btree** trails because pointer-chased nodes lose to a contiguous array for a pure
  priority queue that never needs ordered iteration.
- **Radix trie** is correct and O(constant) but its large constant (8 map-backed
  levels, many allocations) makes it the slowest — asymptotics lose to locality here.
- **Timing wheel** is correct but not competitive: with no external "now" tick its
  base is fixed at the first key, so heterogeneous timeouts push much of the working
  set into the btree overflow, and the bitmap/pointer machinery costs more than an
  array heap. It is a large-N, near-monotonic specialist that this workload doesn't
  reward.

The consistent theme: at the sizes icmpengine runs, **cache behavior and constant
factors decide it, not asymptotics** — which is why a flat array heap (binary or
d-ary) beats the pointer/bucket structures.

## Reproduce

```sh
# tracker micro-benchmark (uniform + mixed), all backends
go test -run '^$' -bench=BenchmarkTracker -benchmem ./...

# d-ary heap fan-out sweep (d = 2,4,8,16)
go test -run '^$' -bench=BenchmarkDaryFanout -benchmem ./...

# engine-level fleet under loss, all backends
go test -run '^$' -bench=BenchmarkEngineFleet -benchmem ./...

# switch the running engine's backend
go run ./cmd/icmpengine -dest 127.0.0.1,::1 -count 10 -backend dary
```

Correctness across the whole latency range (LAN microseconds → Mars-rover hours)
is covered separately by deterministic `testing/synctest` tests
(`engine_synctest_test.go`), which run a fake clock so a 3-hour timeout resolves
in microseconds of real time. Every backend is validated by the shared
`TestTracker*` suite, including an 8000-op differential fuzz test that races each
structure against a reference heap and asserts exact peek agreement at every step.

## Fan-out for the d-ary heap

`BenchmarkDaryFanout` sweeps the fan-out under the mixed workload:

| d | N=1000 | N=100000 |
|--:|--:|--:|
| 2 (binary) | 524 | 679 |
| 4 | 499 | 653 |
| **8** | **478** | 625 |
| 16 | 483 | **608** |

Higher fan-out is shallower and wins here; 8 is the balance point (best at N=1000,
within ~3% of 16 at N=100000), so `BackendDaryHeap` uses **8**.

## Other data structures considered (and not built)

- **Fibonacci heap.** Great amortized asymptotics but famously pointer-heavy and
  cache-hostile; in practice it loses to a flat array heap at these sizes.
- **Skip list, van Emde Boas tree / y-fast trie.** Ordered/integer-key structures
  with attractive bounds but high constant factors and poor locality — the same
  reason the radix trie we *did* build came last. Not worth the complexity here.

The consistent theme, borne out by every table above: at the fleet sizes that
matter, the winner is decided by **cache behavior and constant factors, not
asymptotics** — which is exactly why the flat array heaps (binary and 8-ary) beat
the pointer- and bucket-based structures.
