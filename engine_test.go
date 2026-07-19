package icmpengine_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/randomizedcoder/icmpengine"
)

// These tests run in fake-success mode so they need neither raw-socket
// privileges nor the ping_group_range sysctl, and are safe in CI.
const (
	fakeSuccess    = true
	timeoutT       = 10 * time.Millisecond
	readDeadlineT  = 500 * time.Millisecond
	allowMinorLoss = true
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newFakeEngine(t *testing.T) (*icmpengine.Engine, context.Context) {
	t.Helper()
	eng, err := icmpengine.New(
		icmpengine.WithLogger(testLogger()),
		icmpengine.WithTimeout(timeoutT),
		icmpengine.WithReadDeadline(readDeadlineT),
		icmpengine.WithReceivers(2, 2),
		icmpengine.WithFakeSuccess(fakeSuccess),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		if err := eng.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return eng, ctx
}

type pingCase struct {
	name     string
	ips      []string
	count    int
	interval time.Duration
}

func pingCases() []pingCase {
	return []pingCase{
		{name: "v4", ips: []string{"127.0.0.1"}, count: 10, interval: 10 * time.Millisecond},
		{name: "v6", ips: []string{"::1"}, count: 10, interval: 10 * time.Millisecond},
		{name: "v4+v6", ips: []string{"127.0.0.1", "::1"}, count: 10, interval: 10 * time.Millisecond},
		{name: "v4_alt", ips: []string{"127.0.0.2"}, count: 10, interval: 10 * time.Millisecond},
		{name: "count50", ips: []string{"127.0.0.1", "::1"}, count: 50, interval: 10 * time.Millisecond},
		{name: "fast", ips: []string{"127.0.0.1", "::1"}, count: 20, interval: 1 * time.Millisecond},
	}
}

// maxMedian tolerates the race detector's slowdown.
func maxMedian() time.Duration {
	m := 20 * time.Millisecond
	if icmpengine.IsRaceEnabled {
		m *= 10
	}
	return m
}

func checkResult(t *testing.T, tc pingCase, r icmpengine.Result) {
	t.Helper()
	if len(r.RTTs) == 0 {
		t.Fatalf("%s [%s]: no RTTs", tc.name, r.IP)
	}
	median := r.RTTs[len(r.RTTs)/2]
	if median > maxMedian() {
		t.Errorf("%s [%s]: median %s > %s", tc.name, r.IP, median, maxMedian())
	}
	if r.Successes != tc.count {
		if allowMinorLoss && r.Failures <= 1 {
			t.Logf("%s [%s]: successes %d != %d (minor loss allowed)", tc.name, r.IP, r.Successes, tc.count)
		} else {
			t.Errorf("%s [%s]: successes %d != %d", tc.name, r.IP, r.Successes, tc.count)
		}
	}
	if r.OutOfOrder != 0 {
		t.Logf("%s [%s]: out of order %d", tc.name, r.IP, r.OutOfOrder)
	}
}

// TestPing exercises the blocking single-host Ping.
func TestPing(t *testing.T) {
	eng, ctx := newFakeEngine(t)
	for _, tc := range pingCases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, ip := range tc.ips {
				addr := netip.MustParseAddr(ip)
				r, err := eng.Ping(ctx, addr, tc.count, tc.interval, icmpengine.SortRTTs())
				if err != nil {
					t.Fatalf("Ping(%s): %v", ip, err)
				}
				checkResult(t, tc, r)
			}
		})
	}
}

// TestPingAll exercises concurrent multi-host pinging.
func TestPingAll(t *testing.T) {
	eng, ctx := newFakeEngine(t)
	for _, tc := range pingCases() {
		t.Run(tc.name, func(t *testing.T) {
			targets := make([]icmpengine.Target, 0, len(tc.ips))
			for _, ip := range tc.ips {
				targets = append(targets, icmpengine.Target{
					Addr:     netip.MustParseAddr(ip),
					Count:    tc.count,
					Interval: tc.interval,
					Options:  []icmpengine.PingOption{icmpengine.SortRTTs()},
				})
			}
			results, err := eng.PingAll(ctx, 4, targets)
			if err != nil {
				t.Fatalf("PingAll: %v", err)
			}
			if len(results) != len(targets) {
				t.Fatalf("PingAll returned %d results, want %d", len(results), len(targets))
			}
			for i, r := range results {
				if r.IP != targets[i].Addr {
					t.Errorf("result %d aligned to %s, want %s", i, r.IP, targets[i].Addr)
				}
				checkResult(t, tc, r)
			}
		})
	}
}

// TestStartCloseLoop starts and closes fresh engines repeatedly.
func TestStartCloseLoop(t *testing.T) {
	for i := 0; i < 10; i++ {
		eng, err := icmpengine.New(
			icmpengine.WithLogger(testLogger()),
			icmpengine.WithTimeout(timeoutT),
			icmpengine.WithReadDeadline(readDeadlineT),
			icmpengine.WithFakeSuccess(fakeSuccess),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		if err := eng.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		if _, err := eng.Ping(ctx, netip.MustParseAddr("127.0.0.1"), 3, time.Millisecond, icmpengine.SortRTTs()); err != nil {
			t.Fatalf("Ping: %v", err)
		}
		cancel()
		if err := eng.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
}

// TestPingFakeDrop verifies the DropProbability test hook.
func TestPingFakeDrop(t *testing.T) {
	eng, ctx := newFakeEngine(t)

	t.Run("always_drops", func(t *testing.T) {
		r, err := eng.Ping(ctx, netip.MustParseAddr("127.0.0.1"), 10, 10*time.Millisecond, icmpengine.DropProbability(1))
		if err != nil {
			t.Fatalf("Ping: %v", err)
		}
		if r.Successes != 0 {
			t.Errorf("dropProb=1: successes %d, want 0", r.Successes)
		}
		if r.Failures != r.Count {
			t.Errorf("dropProb=1: failures %d != count %d", r.Failures, r.Count)
		}
	})

	t.Run("partial_drops", func(t *testing.T) {
		const count = 100
		const prob = 0.5
		r, err := eng.Ping(ctx, netip.MustParseAddr("::1"), count, 2*time.Millisecond, icmpengine.DropProbability(prob))
		if err != nil {
			t.Fatalf("Ping: %v", err)
		}
		// Generous band: this is probabilistic over a short run.
		if r.Failures == 0 || r.Failures == count {
			t.Errorf("dropProb=0.5: failures %d looks non-probabilistic (count %d)", r.Failures, count)
		}
	})
}

// TestPingAllManyHosts fans out to many synthetic destinations.
func TestPingAllManyHosts(t *testing.T) {
	eng, ctx := newFakeEngine(t)

	var targets []icmpengine.Target
	for a := 1; a < 3; a++ {
		for b := 1; b < 3; b++ {
			for c := 1; c < 3; c++ {
				for d := 1; d < 3; d++ {
					targets = append(targets, icmpengine.Target{
						Addr:     netip.MustParseAddr(fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)),
						Count:    10,
						Interval: time.Microsecond,
					})
				}
			}
		}
	}

	results, err := eng.PingAll(ctx, 8, targets)
	if err != nil {
		t.Fatalf("PingAll: %v", err)
	}
	for i, r := range results {
		if r.Successes != targets[i].Count {
			t.Errorf("[%s]: successes %d, want %d", r.IP, r.Successes, targets[i].Count)
		}
	}
}

// TestPingErrors covers the input-validation error paths.
func TestPingErrors(t *testing.T) {
	eng, ctx := newFakeEngine(t)

	if _, err := eng.Ping(ctx, netip.MustParseAddr("127.0.0.1"), -1, time.Millisecond); err == nil {
		t.Error("negative count: want error")
	}
	if _, err := eng.Ping(ctx, netip.MustParseAddr("127.0.0.1"), 1<<16, time.Millisecond); err == nil {
		t.Error("count > 65535: want error")
	}
	if _, err := eng.Ping(ctx, netip.Addr{}, 1, time.Millisecond); err == nil {
		t.Error("invalid addr: want error")
	}
	if _, err := eng.Ping(ctx, netip.MustParseAddr("127.0.0.1"), 1, time.Millisecond, icmpengine.PingTimeout(-1)); !errors.Is(err, icmpengine.ErrTimeoutRange) {
		t.Errorf("negative PingTimeout: err = %v, want ErrTimeoutRange", err)
	}
	if _, err := eng.Ping(ctx, netip.MustParseAddr("127.0.0.1"), 1, time.Millisecond, icmpengine.PayloadSize(-1)); !errors.Is(err, icmpengine.ErrPayloadSizeRange) {
		t.Errorf("negative PayloadSize: err = %v, want ErrPayloadSizeRange", err)
	}
	if _, err := eng.Ping(ctx, netip.MustParseAddr("127.0.0.1"), 1, time.Millisecond, icmpengine.PayloadSize(65501)); !errors.Is(err, icmpengine.ErrPayloadSizeRange) {
		t.Errorf("oversized PayloadSize: err = %v, want ErrPayloadSizeRange", err)
	}
}

// TestPingTimeoutOverride confirms a per-ping timeout is accepted and the ping
// still succeeds in fake-success mode.
func TestPingTimeoutOverride(t *testing.T) {
	eng, ctx := newFakeEngine(t)
	r, err := eng.Ping(ctx, netip.MustParseAddr("127.0.0.1"), 5, time.Millisecond, icmpengine.PingTimeout(3*time.Hour))
	if err != nil {
		t.Fatalf("Ping with PingTimeout: %v", err)
	}
	if r.Successes != 5 {
		t.Errorf("successes = %d, want 5", r.Successes)
	}
}

// TestPingNotStarted verifies Ping fails before Start.
func TestPingNotStarted(t *testing.T) {
	eng, err := icmpengine.New(icmpengine.WithLogger(testLogger()), icmpengine.WithFakeSuccess(true))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := eng.Ping(context.Background(), netip.MustParseAddr("127.0.0.1"), 1, time.Millisecond); err == nil {
		t.Error("Ping before Start: want error")
	}
}

// TestNewValidation checks constructor validation.
func TestNewValidation(t *testing.T) {
	if _, err := icmpengine.New(icmpengine.WithTimeout(0)); err == nil {
		t.Error("timeout=0: want error")
	}
	if _, err := icmpengine.New(icmpengine.WithReadDeadline(-1)); err == nil {
		t.Error("readDeadline<0: want error")
	}
	if _, err := icmpengine.New(icmpengine.WithReceivers(0, 0)); err == nil {
		t.Error("no receivers (non-fake): want error")
	}
	if _, err := icmpengine.New(icmpengine.WithFakeSuccess(true), icmpengine.WithDSCP(-1)); !errors.Is(err, icmpengine.ErrDSCPRange) {
		t.Errorf("dscp=-1: err = %v, want ErrDSCPRange", err)
	}
	if _, err := icmpengine.New(icmpengine.WithFakeSuccess(true), icmpengine.WithDSCP(64)); !errors.Is(err, icmpengine.ErrDSCPRange) {
		t.Errorf("dscp=64: err = %v, want ErrDSCPRange", err)
	}
	if _, err := icmpengine.New(icmpengine.WithFakeSuccess(true), icmpengine.WithDSCP(46)); err != nil {
		t.Errorf("dscp=46 (EF): unexpected err = %v", err)
	}
	if _, err := icmpengine.New(icmpengine.WithFakeSuccess(true), icmpengine.WithTTL(-1)); !errors.Is(err, icmpengine.ErrTTLRange) {
		t.Errorf("ttl=-1: err = %v, want ErrTTLRange", err)
	}
	if _, err := icmpengine.New(icmpengine.WithFakeSuccess(true), icmpengine.WithTTL(256)); !errors.Is(err, icmpengine.ErrTTLRange) {
		t.Errorf("ttl=256: err = %v, want ErrTTLRange", err)
	}
	if _, err := icmpengine.New(icmpengine.WithFakeSuccess(true), icmpengine.WithTTL(1)); err != nil {
		t.Errorf("ttl=1: unexpected err = %v", err)
	}
}

func TestIsRace(t *testing.T) {
	t.Logf("IsRaceEnabled: %t", icmpengine.IsRaceEnabled)
}
