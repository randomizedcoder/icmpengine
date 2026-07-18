package icmpengine_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/randomizedcoder/icmpengine"
)

// These tests use testing/synctest (GA in Go 1.25+) to run the engine against a
// fake clock. In fake-success mode there are no real sockets, so the bubble's
// clock advances deterministically the instant every goroutine is durably
// blocked — a 3-hour timeout resolves in microseconds of real time. A test-only
// responder (SetResponder) simulates per-destination round-trip times and drops,
// letting us cover everything from LAN microseconds to interplanetary links.

// latClass describes one simulated destination.
type latClass struct {
	name    string
	addr    netip.Addr
	rtt     time.Duration // simulated round-trip time
	respond bool          // false = dropped/unreachable
	timeout time.Duration // per-ping timeout
	wantOK  bool          // expect success (respond && rtt < timeout)
}

func latencyClasses() []latClass {
	return []latClass{
		{"lan", netip.MustParseAddr("10.0.0.1"), 50 * time.Microsecond, true, 10 * time.Millisecond, true},
		{"metro", netip.MustParseAddr("10.0.0.2"), 2 * time.Millisecond, true, 100 * time.Millisecond, true},
		{"wan", netip.MustParseAddr("10.0.0.3"), 80 * time.Millisecond, true, time.Second, true},
		{"satellite", netip.MustParseAddr("10.0.0.4"), 600 * time.Millisecond, true, 2 * time.Second, true},
		{"moon", netip.MustParseAddr("10.0.0.5"), 2600 * time.Millisecond, true, 10 * time.Second, true},
		{"mars_near", netip.MustParseAddr("10.0.0.6"), 4 * time.Minute, true, time.Hour, true},
		{"mars_far", netip.MustParseAddr("10.0.0.7"), 22 * time.Minute, true, time.Hour, true},
		{"too_slow", netip.MustParseAddr("10.0.0.8"), 5 * time.Second, true, time.Second, false}, // replies after we gave up
		{"unreachable", netip.MustParseAddr("10.0.0.9"), 0, false, 3 * time.Hour, false},         // never replies
	}
}

// responderFor builds an addr->(rtt,respond) responder from a class table.
func responderFor(classes []latClass) func(netip.Addr, int) (time.Duration, bool) {
	byAddr := make(map[netip.Addr]latClass, len(classes))
	for _, c := range classes {
		byAddr[c.addr] = c
	}
	return func(addr netip.Addr, _ int) (time.Duration, bool) {
		c := byAddr[addr]
		return c.rtt, c.respond
	}
}

func newSyncEngine(t *testing.T, classes []latClass) (*icmpengine.Engine, context.Context) {
	t.Helper()
	eng, err := icmpengine.New(
		icmpengine.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		icmpengine.WithTimeout(time.Second),
		icmpengine.WithReadDeadline(time.Second),
		icmpengine.WithFakeSuccess(true),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.SetResponder(responderFor(classes))
	ctx := context.Background()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return eng, ctx
}

func assertClass(t *testing.T, c latClass, r icmpengine.Result, count int) {
	t.Helper()
	if c.wantOK {
		if r.Successes != count || r.Failures != 0 {
			t.Errorf("%s: successes=%d failures=%d, want %d/0", c.name, r.Successes, r.Failures, count)
		}
		// Fake time is exact: every simulated reply has RTT == c.rtt.
		if r.Mean != c.rtt || r.Min != c.rtt || r.Max != c.rtt {
			t.Errorf("%s: rtt min/mean/max = %s/%s/%s, want %s", c.name, r.Min, r.Mean, r.Max, c.rtt)
		}
	} else {
		if r.Failures != count || r.Successes != 0 {
			t.Errorf("%s: failures=%d successes=%d, want %d/0", c.name, r.Failures, r.Successes, count)
		}
	}
}

// TestSyntheticLatencies pings each class on its own and checks the outcome,
// deterministically, in fake time.
func TestSyntheticLatencies(t *testing.T) {
	for _, c := range latencyClasses() {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				eng, ctx := newSyncEngine(t, []latClass{c})
				defer eng.Close()

				const count = 3
				r, err := eng.Ping(ctx, c.addr, count, time.Millisecond, icmpengine.PingTimeout(c.timeout))
				if err != nil {
					t.Fatalf("Ping(%s): %v", c.name, err)
				}
				assertClass(t, c, r, count)
			})
		})
	}
}

// TestMixedFleet pings the whole heterogeneous fleet concurrently through one
// engine, so near-term and hours-away expiries are outstanding simultaneously.
func TestMixedFleet(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		classes := latencyClasses()
		eng, ctx := newSyncEngine(t, classes)
		defer eng.Close()

		const count = 3
		targets := make([]icmpengine.Target, len(classes))
		for i, c := range classes {
			targets[i] = icmpengine.Target{
				Addr:     c.addr,
				Count:    count,
				Interval: time.Millisecond,
				Options:  []icmpengine.PingOption{icmpengine.PingTimeout(c.timeout)},
			}
		}

		results, err := eng.PingAll(ctx, 0, targets)
		if err != nil {
			t.Fatalf("PingAll: %v", err)
		}
		for i, c := range classes {
			assertClass(t, c, results[i], count)
		}
	})
}

// TestInterleavedOutcomes checks that a fast success is not delayed by a slow
// timeout running concurrently, and both resolve correctly.
func TestInterleavedOutcomes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fast := latClass{"fast", netip.MustParseAddr("10.1.0.1"), 20 * time.Millisecond, true, time.Second, true}
		slow := latClass{"slow", netip.MustParseAddr("10.1.0.2"), 0, false, 30 * time.Minute, false}
		eng, ctx := newSyncEngine(t, []latClass{fast, slow})
		defer eng.Close()

		results, err := eng.PingAll(ctx, 0, []icmpengine.Target{
			{Addr: fast.addr, Count: 5, Interval: time.Millisecond, Options: []icmpengine.PingOption{icmpengine.PingTimeout(fast.timeout)}},
			{Addr: slow.addr, Count: 2, Interval: time.Millisecond, Options: []icmpengine.PingOption{icmpengine.PingTimeout(slow.timeout)}},
		})
		if err != nil {
			t.Fatalf("PingAll: %v", err)
		}
		assertClass(t, fast, results[0], 5)
		assertClass(t, slow, results[1], 2)
	})
}
