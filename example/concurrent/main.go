// Command concurrent pings many hosts in parallel with a bounded worker pool
// and prints a per-host summary.
//
//	go run ./example/concurrent -dest 8.8.8.8,8.8.4.4,1.1.1.1 -workers 4
//
// Non-privileged ICMP requires the ping_group_range sysctl on Linux:
//
//	sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/randomizedcoder/icmpengine"
)

func main() {
	dest := flag.String("dest", "127.0.0.1,::1", "comma-separated destination IPs")
	count := flag.Int("count", 20, "number of echo requests per host")
	interval := flag.Duration("interval", 50*time.Millisecond, "interval between requests")
	workers := flag.Int("workers", 4, "max concurrent pingers (0 = one per host)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	eng, err := icmpengine.New(
		icmpengine.WithLogger(logger),
		icmpengine.WithTimeout(500*time.Millisecond),
		icmpengine.WithReadDeadline(time.Second),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "new engine:", err)
		os.Exit(1)
	}

	// Bound total runtime; canceling ctx stops all pingers and the engine.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := eng.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "start engine:", err)
		os.Exit(1)
	}
	defer func() { _ = eng.Close() }()

	var targets []icmpengine.Target
	for h := range strings.SplitSeq(*dest, ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(h))
		if err != nil {
			logger.Warn("skipping bad address", "host", h, "err", err)
			continue
		}
		targets = append(targets, icmpengine.Target{
			Addr:     addr,
			Count:    *count,
			Interval: *interval,
			Options:  []icmpengine.PingOption{icmpengine.SortRTTs()},
		})
	}

	results, err := eng.PingAll(ctx, *workers, targets)
	if err != nil {
		logger.Warn("some pings did not complete", "err", err)
	}

	for i := range results {
		r := &results[i]
		loss := 0.0
		if r.Count > 0 {
			loss = 100 * float64(r.Failures) / float64(r.Count)
		}
		fmt.Printf("%-39s success=%3d loss=%5.1f%% mean=%s\n", r.IP, r.Successes, loss, r.Mean)
	}
}
