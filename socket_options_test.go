package icmpengine_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/randomizedcoder/icmpengine"
)

// skipUnlessNonPrivICMP skips the test unless a non-privileged ICMP engine can
// be started here (permissive net.ipv4.ping_group_range and IPv4+IPv6 loopback).
func skipUnlessNonPrivICMP(t *testing.T) {
	t.Helper()
	eng, err := icmpengine.New(icmpengine.WithLogger(nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Skipf("non-privileged ICMP unavailable: %v", err)
	}
	_ = eng.Close()
}

// startRealEngine builds and starts an engine on real sockets, registering
// cleanup. It fails the test (rather than skipping) on Start errors, so call
// skipUnlessNonPrivICMP first where the environment may lack permissions.
func startRealEngine(t *testing.T, opts ...icmpengine.Option) (*icmpengine.Engine, context.Context) {
	t.Helper()
	base := []icmpengine.Option{
		icmpengine.WithLogger(nil),
		icmpengine.WithTimeout(time.Second),
		icmpengine.WithReadDeadline(time.Second),
	}
	eng, err := icmpengine.New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = eng.Close() })
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return eng, ctx
}

// TestWithSourceLoopback binds to 127.0.0.1 and pings it.
func TestWithSourceLoopback(t *testing.T) {
	skipUnlessNonPrivICMP(t)
	eng, ctx := startRealEngine(t, icmpengine.WithSource(netip.MustParseAddr("127.0.0.1")))
	res, err := eng.Ping(ctx, netip.MustParseAddr("127.0.0.1"), 1, 0)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if res.Successes != 1 {
		t.Fatalf("successes = %d, want 1", res.Successes)
	}
}

// TestWithSourceInvalid confirms binding to a non-local source fails at Start.
func TestWithSourceInvalid(t *testing.T) {
	skipUnlessNonPrivICMP(t)
	// 192.0.2.1 (TEST-NET-1, RFC 5737) is not a local address, so bind must fail.
	eng, err := icmpengine.New(icmpengine.WithLogger(nil), icmpengine.WithSource(netip.MustParseAddr("192.0.2.1")))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = eng.Close() }()
	if err := eng.Start(context.Background()); err == nil {
		t.Fatal("Start with non-local source: want error, got nil")
	}
}

// TestWithDontFragmentLoopback confirms an engine with DF set starts and pings
// loopback (a small packet is well under the loopback MTU, so DF does not drop it).
func TestWithDontFragmentLoopback(t *testing.T) {
	skipUnlessNonPrivICMP(t)
	eng, ctx := startRealEngine(t, icmpengine.WithDontFragment(true))
	res, err := eng.Ping(ctx, netip.MustParseAddr("127.0.0.1"), 1, 0, icmpengine.PayloadSize(56))
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if res.Successes != 1 {
		t.Fatalf("successes = %d, want 1", res.Successes)
	}
}
