package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/profile"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/randomizedcoder/icmpengine"
)

var (
	// Passed by "go build -ldflags" for the show version
	tag    string
	commit string
	date   string
)

func main() {
	dest := flag.String("dest", "127.0.0.1,::1", "Destination IPs to ping, comma separated, e.g. 8.8.8.8,8.8.4.4")
	count := flag.Int("count", 10, "Count of icmps to send.")
	interval := flag.Duration("interval", 10*time.Millisecond, "Interval between icmp echo request messages sent.")
	timeout := flag.Duration("timeout", 200*time.Millisecond, "Timeout to wait for an echo response before declaring it dropped.")
	readDeadline := flag.Duration("readDeadline", 3*time.Second, "Receiver socket read deadline. Bounds how quickly shutdown is noticed.")
	r4 := flag.Int("rPP4", 2, "Receivers IPv4")
	r6 := flag.Int("rPP6", 2, "Receivers IPv6")
	splayReceivers := flag.Bool("splay", false, "Splay the receiver start times")
	concurrency := flag.Int("concurrency", 0, "Max concurrent pingers (0 = one per destination)")

	version := flag.Bool("version", false, "show version")
	logLevel := flag.String("log", "info", "Log level: debug, info, warn, error")
	promBind := flag.String("promBind", ":8889", "Prometheus /metrics HTTP bind socket")
	promPath := flag.String("promPath", "/metrics", "Prometheus metrics path")
	pprof := flag.String("pprof", "", "enable profiling mode, options [cpu, mem, mutex, block, trace]")

	flag.Parse()

	if *version {
		fmt.Println("icmpengine\ttag:", tag, "\tcommit:", commit, "\tcompile date(UTC):", date)
		os.Exit(0)
	}

	// ICMP sequence numbers are uint16; bound the count.
	if *count < 0 || *count > math.MaxUint16 {
		fmt.Fprintf(os.Stderr, "count must be between 0 and %d (icmp sequence is uint16)\n", math.MaxUint16)
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))

	// "github.com/pkg/profile"
	// e.g. ./icmpengine -pprof cpu ; go tool pprof -http=":8081" icmpengine cpu.pprof
	switch *pprof {
	case "cpu":
		defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()
	case "mem":
		defer profile.Start(profile.MemProfile, profile.ProfilePath(".")).Stop()
	case "mutex":
		defer profile.Start(profile.MutexProfile, profile.ProfilePath(".")).Stop()
	case "block":
		defer profile.Start(profile.BlockProfile, profile.ProfilePath(".")).Stop()
	case "trace":
		defer profile.Start(profile.TraceProfile, profile.ProfilePath(".")).Stop()
	}

	startPrometheus(logger, *promBind, *promPath)

	// Shut down cleanly on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eng, err := icmpengine.New(
		icmpengine.WithLogger(logger),
		icmpengine.WithTimeout(*timeout),
		icmpengine.WithReadDeadline(*readDeadline),
		icmpengine.WithReceivers(*r4, *r6),
		icmpengine.WithSplayReceivers(*splayReceivers),
	)
	if err != nil {
		logger.Error("creating engine", "err", err)
		os.Exit(1)
	}
	if err := eng.Start(ctx); err != nil {
		logger.Error("starting engine", "err", err)
		os.Exit(1)
	}
	defer func() {
		if err := eng.Close(); err != nil {
			logger.Error("engine closed with error", "err", err)
		}
	}()

	targets, err := parseTargets(*dest, *count, *interval)
	if err != nil {
		logger.Error("bad destination", "err", err)
		os.Exit(1)
	}

	results, err := eng.PingAll(ctx, *concurrency, targets)
	if err != nil {
		logger.Error("ping", "err", err)
	}
	for i := range results {
		r := &results[i]
		loss := 0.0
		if r.Count > 0 {
			loss = 100 * float64(r.Failures) / float64(r.Count)
		}
		fmt.Printf("%-39s sent=%d success=%d loss=%.1f%% min=%s mean=%s max=%s\n",
			r.IP, r.Count, r.Successes, loss, r.Min, r.Mean, r.Max)
	}
}

// startPrometheus serves the metrics endpoint in the background.
func startPrometheus(logger *slog.Logger, bind, path string) {
	http.Handle(path, promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{EnableOpenMetrics: true},
	))
	srv := &http.Server{Addr: bind, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("prometheus http listener failed", "err", err)
		}
	}()
	logger.Info("prometheus listener started", "bind", bind, "path", path)
}

// parseTargets builds the PingAll target list from a comma-separated dest list.
func parseTargets(dest string, count int, interval time.Duration) ([]icmpengine.Target, error) {
	var targets []icmpengine.Target
	for ip := range strings.SplitSeq(dest, ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil {
			return nil, fmt.Errorf("%q: %w", ip, err)
		}
		targets = append(targets, icmpengine.Target{
			Addr:     addr,
			Count:    count,
			Interval: interval,
			Options:  []icmpengine.PingOption{icmpengine.SortRTTs()},
		})
	}
	return targets, nil
}

// parseLevel maps a log-level string to a slog.Level.
func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
