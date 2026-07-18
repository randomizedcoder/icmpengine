// Command simple pings a single host and prints the round-trip statistics.
//
// It is the smallest example of embedding icmpengine:
//
//	go run ./example/simple -dest 8.8.8.8 -count 5
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
	"time"

	"github.com/randomizedcoder/icmpengine"
)

func main() {
	dest := flag.String("dest", "127.0.0.1", "destination IP to ping")
	count := flag.Int("count", 10, "number of echo requests")
	interval := flag.Duration("interval", 100*time.Millisecond, "interval between requests")
	flag.Parse()

	addr, err := netip.ParseAddr(*dest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -dest %q: %v\n", *dest, err)
		os.Exit(1)
	}

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

	ctx := context.Background()
	if err := eng.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "start engine:", err)
		os.Exit(1)
	}
	defer func() { _ = eng.Close() }()

	res, err := eng.Ping(ctx, addr, *count, *interval, icmpengine.SortRTTs())
	if err != nil {
		fmt.Fprintln(os.Stderr, "ping:", err)
		os.Exit(1)
	}

	fmt.Printf("%s: sent=%d success=%d failed=%d min=%s mean=%s max=%s\n",
		res.IP, res.Count, res.Successes, res.Failures, res.Min, res.Mean, res.Max)
}
