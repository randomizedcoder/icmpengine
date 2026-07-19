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
be swapped and benchmarked without touching the engine. Two ship today:

- **`BackendHeap`** — `container/heap` min-heap keyed by expiry + an
  `addr→seq→*pending` index for O(1) lookup / O(log n) removal. Peek is O(1). No
  external dependency.
- **`BackendBTree`** — `github.com/google/btree` (generic), ordered by
  `(expiry, addr, seq)`, same index for removal. All ops O(log n).

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

### Tracker micro-benchmark — `uniform` (monotonic; heap's & list's best case)

| N | heap | btree | list |
|--:|--:|--:|--:|
| 100 | 532 | 621 | 408 |
| 1000 | 661 | 812 | 463 |
| 10000 | 844 | 1012 | 582 |

The list wins here — but only because monotonic expiry lets it `PushBack`. It is
*incorrect* the moment timeouts differ, which is why it is a baseline, not a
backend.

### Tracker micro-benchmark — `mixed` (heterogeneous; the realistic case)

| N | heap | btree |
|--:|--:|--:|
| 100 | 486 | 716 |
| 1000 | 520 | 835 |
| 10000 | 664 | 1118 |
| 100000 | 691 | 1814 |

Heap wins at every size, and the gap **widens** with N — ~1.5× at 100, ~2.6× at
100k.

### Engine-level fleet under packet loss

| targets | heap | btree |
|--:|--:|--:|
| 100 | ~3.96 ms/op | ~4.39 ms/op (+11%) |
| 1000 | ~23.1 ms/op | ~26.1 ms/op (+13%) |

End to end, most of each packet's ~5–8µs goes to goroutine scheduling, channel
sends and timers — but the queue is a **real and growing fraction**: ~11% at 100
targets, ~13% at 1000, trending toward the multiples the micro-benchmark shows at
tens of thousands outstanding.

## Why the array heap wins

For a pure priority queue that never needs ordered iteration, a binary heap's
contiguous, cache-friendly array beats a btree's pointer-chased nodes. Both are
O(log n), but the heap's constant factors and memory locality are far better, and
allocations are effectively identical (dominated by the `*pending` itself). A
btree earns its keep with range scans and ordered traversal — neither of which
this workload uses.

## Reproduce

```sh
# tracker micro-benchmark (uniform + mixed), all backends
go test -run '^$' -bench=BenchmarkTracker -benchmem ./...

# engine-level fleet under loss, heap vs btree
go test -run '^$' -bench=BenchmarkEngineFleet -benchmem ./...

# switch the running engine's backend
go run ./cmd/icmpengine -dest 127.0.0.1,::1 -count 10 -backend btree
```

Correctness across the whole latency range (LAN microseconds → Mars-rover hours)
is covered separately by deterministic `testing/synctest` tests
(`engine_synctest_test.go`), which run a fake clock so a 3-hour timeout resolves
in microseconds of real time.

## Other data structures considered

The heap won, but it is worth recording what else could fit — and why we did not
reach for it. The abstraction makes any of these a self-contained addition behind
`expiryTracker`.

- **d-ary heap (e.g. 4-ary).** A heap with higher fan-out is shallower, so
  sift-down touches fewer, more cache-local nodes. This is the lowest-risk
  potential win over the current binary heap and would be a cheap A/B test. Most
  likely the "am I overlooking something?" answer for a modest improvement.

- **Hierarchical timing wheels.** The structure purpose-built for exactly this —
  managing many timers over a wide range of durations — and what the Linux
  kernel, Netty and Kafka use. Insert/delete/expire are **O(1) amortized** (no log
  factor), so it scales past the heap at very large N, and cascading wheels handle
  µs-to-hours ranges cleanly. Trade-offs: expiry is **bucketed** to a tick
  granularity rather than exact (fine for ICMP, where ms precision is plenty), and
  it changes the expirer's driver model from "sleep until the soonest expiry" to
  "advance ticks and fire the current bucket." This is the most compelling
  alternative if icmpengine ever needs to track *very* large numbers of
  outstanding pings; the added complexity is why the heap remains the default.

- **Radix / monotone bucket heap.** Because a freshly inserted expiry
  (`now + timeout`) is always ≥ the last one that fired, the extract-min sequence
  is monotone — the precondition a radix heap needs for **O(1) amortized**
  operations. Attractive in theory, but bucket sizing and arbitrary deletion are
  fiddlier than a timing wheel, which is the more practical embodiment of the same
  idea.

- **Pairing heap.** O(1) insert and good amortized bounds with far less overhead
  than a Fibonacci heap, but still pointer-heavy with poor cache behavior; in
  practice it rarely beats a flat array heap at these sizes.

- **Fibonacci heap, skip list, van Emde Boas tree.** Theoretically interesting
  (great asymptotics / integer-key tricks) but dominated in practice here by high
  constant factors and poor locality. Not worth the complexity for this workload.

The consistent theme: at the fleet sizes that matter, the winner is decided by
**cache behavior and constant factors, not asymptotics** — which is exactly why a
flat array heap beats a pointer-based tree. A timing wheel is the one structure
that could change that story at extreme scale, by trading exact-time ordering for
O(1) bucketed expiry.
