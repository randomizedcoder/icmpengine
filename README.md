# ICMPEngine

ICMPEngine is a small, embeddable library for sending non-privileged ICMP echo
requests and receiving replies concurrently, without blocking on per-packet
timeouts.

Key features:
- One IPv4 socket and one IPv6 socket; matches replies to requests across many destinations concurrently.
- Does not wait for a packet's timeout before sending the next — outstanding pings are tracked centrally.
- A single expiry timer tracks the soonest-expiring outstanding ping using [container/heap](https://pkg.go.dev/container/heap) (a typed priority queue). Timeouts are per-ping, so one engine can mix a 10ms LAN host and an hours-away link (see `PingTimeout`).
- Built to embed: `context.Context` cancellation, functional-options construction, errors returned instead of `log.Fatal`, and standard-library [log/slog](https://pkg.go.dev/log/slog) logging (pass `nil` for none — no logging dependency).
- Leverages [golang.org/x/net/icmp](https://pkg.go.dev/golang.org/x/net/icmp) and IPPROTO_ICMP NonPrivilegedPing sockets ([lwn.net/Articles/422330](https://lwn.net/Articles/422330/)).
- Uses the standard library [net/netip](https://pkg.go.dev/net/netip) IP type.
- Note: packet size and DSCP bits are NOT currently supported.

```
go get github.com/randomizedcoder/icmpengine
```

Non-privileged ICMP on Linux requires the ping group range to include your gid:

```
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
```

## Quickstart

Ping a single host (see [./example/simple](./example/simple/main.go)):

```go
package main

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/randomizedcoder/icmpengine"
)

func main() {
	eng, err := icmpengine.New(
		icmpengine.WithTimeout(500 * time.Millisecond),
	)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	if err := eng.Start(ctx); err != nil {
		panic(err)
	}
	defer eng.Close()

	res, err := eng.Ping(ctx, netip.MustParseAddr("8.8.8.8"), 10, 100*time.Millisecond, icmpengine.SortRTTs())
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s: success=%d/%d min=%s mean=%s max=%s\n",
		res.IP, res.Successes, res.Count, res.Min, res.Mean, res.Max)
}
```

Ping many hosts concurrently with a bounded worker pool
(see [./example/concurrent](./example/concurrent/main.go)):

```go
targets := []icmpengine.Target{
	{Addr: netip.MustParseAddr("8.8.8.8"), Count: 20, Interval: 50 * time.Millisecond},
	{Addr: netip.MustParseAddr("1.1.1.1"), Count: 20, Interval: 50 * time.Millisecond},
}
results, err := eng.PingAll(ctx, 4 /* workers */, targets) // results aligned to targets
```

Runnable examples and a fuller CLI:

```
go run ./example/simple     -dest 8.8.8.8 -count 5
go run ./example/concurrent -dest 8.8.8.8,1.1.1.1 -workers 4
go run ./cmd/icmpengine     -dest 127.0.0.1,::1 -count 10
```

### Logging

The engine logs via `log/slog`. Pass `icmpengine.WithLogger(l)` to supply a
`*slog.Logger`, or omit it (or pass `nil`) to disable logging entirely — there is
no logging dependency to pull in.

### Per-ping timeouts

`WithTimeout` sets the engine's default, but each `Ping` (and each `PingAll`
`Target`) can override it with `PingTimeout`, so different destinations can wait
different amounts of time — a 10ms LAN host and an hours-away interplanetary link
in the same engine:

```go
res, _ := eng.Ping(ctx, lan,  5, time.Second, icmpengine.PingTimeout(10*time.Millisecond))
res, _ := eng.Ping(ctx, mars, 5, time.Minute, icmpengine.PingTimeout(3*time.Hour))
```

The timeout machinery is covered by deterministic `testing/synctest` tests that
exercise the full range (LAN microseconds → Mars-rover hours) in fake time, so a
3-hour timeout test runs in microseconds.

### Expiry backend

Outstanding pings are tracked in a swappable "expiry tracker" (a priority queue
with arbitrary removal). Six backends are built in and selectable at construction,
all validated by the same correctness suite:

- `icmpengine.BackendHeap` — `container/heap` binary min-heap (**default**; O(1) peek, no external dependency).
- `icmpengine.BackendDaryHeap` — 8-ary array heap (**fastest** on the realistic workload).
- `icmpengine.BackendPairing` — pairing heap.
- `icmpengine.BackendBTree` — [`github.com/google/btree`](https://github.com/google/btree).
- `icmpengine.BackendRadix` — fixed-base radix trie.
- `icmpengine.BackendTimingWheel` — hierarchical timing wheel + btree overflow.

```go
eng, _ := icmpengine.New(icmpengine.WithExpiryBackend(icmpengine.BackendDaryHeap))
```

The CLI exposes this as `-backend heap|dary|pairing|btree|radix|wheel`. `BackendHeap`
remains the default, but benchmarking across `uniform` and `mixed` (heterogeneous
per-ping timeouts µs…hours) workloads plus the engine-level fleet shows the **8-ary
heap is consistently fastest** (same allocations, just a shallower, more
cache-friendly array). The flat array heaps beat the pointer/bucket structures
because at these sizes cache behavior and constant factors decide it, not asymptotics.

See **[docs/backends.md](./docs/backends.md)** for a per-backend guide (what each
is, pros/cons, when to pick it) and **[docs/benchmarking.md](./docs/benchmarking.md)**
for the full methodology, result tables, and the fan-out sweep.

<img src="./icmpengine.png" alt="xtcp diagram" width="75%" height="75%"/>

## Nix

This repo ships a Nix flake (thin `flake.nix` orchestrator + modular `nix/`).

```
nix develop                     # dev shell (Go, golangci-lint, gopls, delve, ...)
nix build .#icmpengine          # main binary (default variant)
nix build .#icmpengine-debug    # keeps symbols + DWARF
nix build .#icmpengine-stripped # smallest
nix run   .#default -- --dest 127.0.0.1,::1 --count 5

nix flake check                 # gofmt + nix-fmt + go-vet + golangci (Tier 0+1) + gosec + version smoke + race
```

Static analysis is tiered (like the reference xtcp2 flake):

```
lint-quick                      # Tier 0 golangci (~30s) — dev shell helper
lint                            # Tier 1 golangci (~2min, CI-gating)
lint-comprehensive              # Tier 2 golangci (~10min, non-gating)
nix build .#golangci-lint-comprehensive   # Tier 2 as a package
nix build .#quality-report && cat result/quality-report.md   # every tool, one report
nix run   .#quality-report      # print the aggregated report
```

`nix flake check` gates Tier 0, Tier 1, gosec, gofmt, nix-fmt, go-vet, the
version smoke and the race detector. Tier 2 (complexity/duplication/naming) is
surfaced for awareness via the `quality-report` and the comprehensive package,
but does not gate CI.

OCI image (scratch-based, single binary):

```
nix build .#oci-icmpengine && ./result | docker load
docker run --rm icmpengine:latest --version
# runtime ping needs NET_RAW or a permissive ping_group_range:
docker run --rm --sysctl net.ipv4.ping_group_range="0 2147483647" \
  icmpengine:latest --dest 127.0.0.1 --count 3
```

Consumers can pull the binary via the overlay
(`inputs.icmpengine.overlays.default` → `pkgs.icmpengine`).

Note: the hermetic `nix flake check` runs only the socket-free unit tests; the
loopback ICMP integration tests need privileges the Nix sandbox lacks and run in
GitHub Actions instead.

## Dependency licenses

Dependancy                                                     | License         | Link
---                                                            | ---             | ---
Golang                                                         | BSD             | https://golang.org/LICENSE
github.com/google/btree v1.1.3                                 | Apache 2.0      | https://github.com/google/btree/blob/master/LICENSE
github.com/go-cmd/cmd v1.4.3                                   | MIT             | https://github.com/go-cmd/cmd/blob/master/LICENSE
github.com/pkg/profile v1.7.0                                  | BSD             | https://github.com/pkg/profile/blob/master/LICENSE
github.com/prometheus/client_golang v1.23.2                    | Apache 2.0      | https://github.com/prometheus/client_golang/blob/master/LICENSE
golang.org/x/net v0.57.0                                       | BSD             | https://golang.org/LICENSE

The IP type is the standard library [net/netip](https://pkg.go.dev/net/netip),
and logging is the standard library [log/slog](https://pkg.go.dev/log/slog), so
neither `inet.af/netaddr` nor `hashicorp/go-hclog` is a dependency any more.

The **library** needs only `golang.org/x/net` and `github.com/google/btree`
(the latter tiny, with zero transitive dependencies). The remaining modules are
used solely by the `cmd/icmpengine` CLI (profiling, Prometheus metrics, and the
root sysctl helper), so embedding the library does not pull them in.

```
$ cat go.mod
module github.com/randomizedcoder/icmpengine

go 1.26.4

require (
	github.com/go-cmd/cmd v1.4.3
	github.com/google/btree v1.1.3
	github.com/pkg/profile v1.7.0
	github.com/prometheus/client_golang v1.23.2
	golang.org/x/net v0.57.0
)
```

How to tag
```
git tag
git tag -a v1.0.1 -m "v1.0.1"
git push origin --tags
```