# Expiry backends

icmpengine tracks every outstanding ping in a "expiry tracker" — a **priority
queue with arbitrary removal** — so the expirer can find the soonest ping to time
out and the receiver can remove one the instant its reply arrives. That structure
is pluggable: six backends ship, all selectable at construction and all validated
by the same correctness suite (peek order, interior/duplicate removal, deleteAddr,
plus an 8000-op differential fuzz test against a reference heap).

This page is the **decision guide** — what each backend is, its pros and cons, and
when to pick it. For the full measurement methodology and workloads see
[benchmarking.md](./benchmarking.md).

## Selecting a backend

```go
eng, _ := icmpengine.New(icmpengine.WithExpiryBackend(icmpengine.BackendDaryHeap))
```

CLI: `-backend heap|dary|pairing|btree|radix|wheel`.

The operations the backend must serve (all under one mutex, so implementations
need not be concurrency-safe): `push` (a packet is sent), `remove(addr,seq)` (a
reply arrived *or* a timeout fired — the common case), `peek()` (the expirer reads
the soonest, very frequent), and `deleteAddr` (a Ping finished). `N` is the number
of pings outstanding at once.

## The backends

### `BackendHeap` — binary `container/heap` *(default)*

A binary min-heap keyed by expiry plus an `addr→seq→*pending` index for O(1)
lookup / O(log n) removal. Peek is O(1).

- **Pros:** simple, well-understood, zero dependencies, O(1) peek, cache-friendly
  contiguous array, 3 allocs/op.
- **Cons:** slightly deeper than a higher-fan-out heap, so a touch slower on the
  remove-heavy churn.
- **Use when:** you want the safe, obvious default. It is the baseline everything
  else is measured against.

### `BackendDaryHeap` — 8-ary array heap *(fastest)*

The same array-heap algorithm with fan-out 8 instead of 2. A shallower tree means
sift-down touches fewer, more cache-local nodes.

- **Pros:** **fastest across the realistic (mixed) and engine-level benchmarks**,
  at the *same* 3 allocs/op as the binary heap; still O(1) peek, zero dependencies.
  Fan-out 8 was chosen from a 2/4/8/16 sweep.
- **Cons:** scans up to 8 children per sift step (cheap); marginally more code than
  the stdlib heap.
- **Use when:** you want the best measured performance with no downside. A one-line
  swap from the default.

### `BackendPairing` — pairing heap

A multiway tree with O(1) push/peek and amortized-log removal; arbitrary removal
cuts a node via child/sibling/prev back-pointers and re-melds.

- **Pros:** O(1) push, competitive overall, **best on the uniform (monotonic)
  workload**.
- **Cons:** pointer-based (one extra allocation per entry for its node), so slightly
  behind the array heaps on the mixed workload and a bit more cache-hostile.
- **Use when:** insert-dominated, largely-monotonic timeout patterns.

### `BackendBTree` — `github.com/google/btree`

A generic B-tree ordered by `(expiry, addr, seq)` with the same index for removal;
all operations O(log n).

- **Pros:** battle-tested library; supports ordered iteration/range scans (which
  this workload does not use).
- **Cons:** pointer-chased nodes lose to a contiguous array for a pure priority
  queue; slower and its lead over the heaps *worsens* with N.
- **Use when:** you separately need ordered traversal, or you already depend on it.

### `BackendRadix` — fixed-base radix trie

An MSD digit trie over the 64-bit `expiry.UnixNano()` key (8-bit digits → 8 levels),
full-width leaves so peek is exact; an occupancy bitmap per node finds the min
child in O(1). All ops are O(8) — **constant in N**.

- **Pros:** genuinely O(constant); no monotonicity assumption (unlike a classic
  Dijkstra radix heap, which is *incorrect* here — arbitrary removal and
  non-monotone inserts violate its invariant).
- **Cons:** the constant is large — 8 map-backed levels and ~9–13 allocs/op make it
  the **slowest** in practice. Asymptotics lose to locality at these sizes.
- **Use when:** essentially a study in "O(constant) ≠ fast." Not recommended for
  production here.

### `BackendTimingWheel` — hierarchical timing wheel

Four absolute-time bucket levels (µs/ms/s/1000s) with per-slot sorted lists and an
occupancy bitmap, plus a `google/btree` overflow for out-of-range keys.

- **Pros:** O(1) insert/remove; the family the Linux kernel/Netty/Kafka use for
  large timer sets; strongest at very large N under near-monotonic load.
- **Cons:** this abstraction has no external "now" tick, so its base is fixed at the
  first key — heterogeneous timeouts push much of the working set into the btree
  overflow, and the bitmap/pointer machinery costs more than an array. Not
  competitive on the mixed workload.
- **Use when:** near-monotonic, very-large-N timer sets. For icmpengine's workload
  the array heaps win.

## Results at a glance

Mixed workload (heterogeneous per-ping timeouts µs…hours; the realistic case),
ns/op on the dev machine — lower is better:

| backend | N=1000 | N=100000 | allocs/op | notes |
|---|--:|--:|--:|---|
| **dary8** | **504** | **680** | 3 | fastest |
| heap (default) | 540 | 732 | 3 | safe baseline |
| pairing | 587 | 768 | 4 | best on uniform |
| btree | 943 | 1906 | 3 | ordered iteration you don't need |
| wheel | 871 | 1997 | 4 | large-N/monotonic specialist |
| radix | 1867 | 2179 | ~9–13 | O(const), large const |

Engine-level (`BenchmarkEngineFleet`, 1000 targets under packet loss) confirms the
same ordering: dary8 < pairing < heap < btree < wheel < radix.

## Recommendation

- **Default `BackendHeap`** is the safe choice and stays the default.
- **`BackendDaryHeap` is the fastest** with no downside (same allocations) — a
  one-line opt-in, and a reasonable future default.
- The pointer/bucket structures (btree, wheel, radix) are correct and available,
  but at the fleet sizes icmpengine runs, **cache behavior and constant factors
  decide it, not asymptotics** — which is why the flat array heaps win.

See [benchmarking.md](./benchmarking.md) for the workloads, the fan-out sweep, the
full per-size tables, and how to reproduce.
