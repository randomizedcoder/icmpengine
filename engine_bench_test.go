package icmpengine_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/randomizedcoder/icmpengine"
)

// BenchmarkEngineFleet measures the whole engine (goroutines, channels, timers
// and the expiry queue together) pinging a fleet under packet loss, comparing
// the heap and btree backends. Unlike the synctest tests this runs in real time,
// so the per-ping timeouts are scaled down to sub-millisecond while kept distinct
// (heterogeneous expiries) and ~20% of packets are dropped so they time out.
//
// It answers "does the queue backend move the needle at the engine level?" —
// and it does, by a share that grows with the fleet: most of each packet's cost
// is scheduling, channel sends and timers, but the queue is a real fraction of
// it. Measured here heap beats btree by roughly 9% at 100 targets and ~17% at
// 1000, and the tracker micro-benchmark (BenchmarkTracker) shows the gap widening
// to multiples at tens of thousands outstanding. BackendHeap is the default.
func BenchmarkEngineFleet(b *testing.B) {
	backends := []struct {
		name string
		opt  icmpengine.Option
	}{
		{"heap", icmpengine.WithExpiryBackend(icmpengine.BackendHeap)},
		{"btree", icmpengine.WithExpiryBackend(icmpengine.BackendBTree)},
	}
	sizes := []int{100, 1000}
	const count = 5

	const rtt = 50 * time.Microsecond
	timeoutFor := func(i int) time.Duration {
		// Distinct, small, heterogeneous: 400µs .. ~720µs.
		return 400*time.Microsecond + time.Duration(i%64)*5*time.Microsecond
	}
	lost := func(i, seq int) bool { return (i+7*seq)%5 == 0 } // ~20% loss

	for _, bk := range backends {
		for _, n := range sizes {
			b.Run(fmt.Sprintf("%s/targets=%d", bk.name, n), func(b *testing.B) {
				addrs := make([]netip.Addr, n)
				idx := make(map[netip.Addr]int, n)
				for i := range addrs {
					addrs[i] = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
					idx[addrs[i]] = i
				}

				eng, err := icmpengine.New(
					icmpengine.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
					icmpengine.WithFakeSuccess(true),
					bk.opt,
				)
				if err != nil {
					b.Fatalf("New: %v", err)
				}
				eng.SetResponder(func(a netip.Addr, seq int) (time.Duration, bool) {
					if lost(idx[a], seq) {
						return 0, false // dropped: times out at the target's timeout
					}
					return rtt, true
				})
				ctx := context.Background()
				if err := eng.Start(ctx); err != nil {
					b.Fatalf("Start: %v", err)
				}
				defer eng.Close()

				targets := make([]icmpengine.Target, n)
				for i := range targets {
					targets[i] = icmpengine.Target{
						Addr:     addrs[i],
						Count:    count,
						Interval: 0,
						Options:  []icmpengine.PingOption{icmpengine.PingTimeout(timeoutFor(i))},
					}
				}

				b.ReportAllocs()
				for b.Loop() {
					if _, err := eng.PingAll(ctx, 0, targets); err != nil {
						b.Fatalf("PingAll: %v", err)
					}
				}
				b.ReportMetric(float64(n*count), "packets/op")
			})
		}
	}
}
