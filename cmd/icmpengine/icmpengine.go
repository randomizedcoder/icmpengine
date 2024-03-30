package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"net/netip"

	"github.com/hashicorp/go-hclog"
	"github.com/pkg/profile"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/EdgeCast/icmpengine"
)

const (
	debugLevel = 11

	promListenCst           = ":8889"
	promPathCst             = "/metrics"
	promMaxRequestsInFlight = 10
	promEnableOpenMetrics   = true

	cancelSleepTime   = 5 * time.Second
	signalChannelSize = 10
)

var (
	// Passed by "go build -ldflags" for the show version
	tag    string
	commit string
	date   string
)

func main() {

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	go initSignalHandler(cancel)

	version := flag.Bool("version", false, "version")

	dest := flag.String("dest", "127.0.0.1,::1", "Destination IPs to ping, comma seperated, e.g. 8.8.8.8,8.8.4.4")
	destTimeout := flag.String("destTimeout", "150ms,100ms", "Timeout for each ping dest")
	count := flag.Int("count", 10, "Count of icmps to send.")
	interval := flag.Duration("interval", 10*time.Millisecond, "Interval between icmp echo request message sent.")
	//timeout := flag.Duration("timeout", 200*time.Millisecond, "Timeout to wait for arrival of a echo response message, before declaring it dropped.")
	readDeadline := flag.Duration("readDeadline", 3*time.Second, "Receiver socket .SetReadDeadline timeout.  Essentailly, how long to wait before checking the done channel.")
	r4 := flag.Int("rPP4", 2, "Receivers IPv4")
	r6 := flag.Int("rPP6", 2, "Receivers IPv6")
	splayReceivers := flag.Bool("splay", false, "Splay the receivers")
	blocking := flag.Bool("blocking", false, "blocking or channel mode")

	di := flag.Int("di", 1, "ICMPengine debug level")
	ds := flag.Int("ds", 1, "socket debug level")
	dr := flag.Int("dr", 1, "receiver debug level")
	de := flag.Int("de", 1, "expirers debug level")
	dp := flag.Int("dp", 1, "pPingers debug level")

	logLevel := flag.String("log", "info", "Log level: NoLevel, Trace, Debug, Info, Warn, Error, Off")
	promListen := flag.String("promListen", promListenCst, "Prometheus HTTP bind socket")
	promPath := flag.String("promPath", promPathCst, "Prometheus metrics path")

	pprof := flag.String("pprof", "", "enable profiling mode, options [cpu, mem, mutex, block, trace]")

	flag.Parse()

	if *version {
		fmt.Println("monitor\ttag:", tag, "\tcommit:", commit, "\tcompile date(UTC):", date)
		os.Exit(0)
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "icmpengine",
		Level: hclog.LevelFromString(*logLevel),
	})

	// "github.com/pkg/profile"
	// https://dave.cheney.net/2013/07/07/introducing-profile-super-simple-profiling-for-go-programs
	// e.g. ./icmpengine -pprof trace
	// go tool trace trace.out
	// e.g. ./icmpengine -pprof cpu
	// go tool pprof -http=":8081" icmpengine cpu.pprof
	logger.Info(fmt.Sprintf("*pprof:%s", *pprof))
	switch *pprof {
	case "cpu":
		defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()
	case "mem":
		defer profile.Start(profile.MemProfile, profile.ProfilePath(".")).Stop() // heap
	case "mutex":
		defer profile.Start(profile.MutexProfile, profile.ProfilePath(".")).Stop()
	case "block":
		defer profile.Start(profile.BlockProfile, profile.ProfilePath(".")).Stop()
	case "trace":
		defer profile.Start(profile.TraceProfile, profile.ProfilePath(".")).Stop()
	default:
		logger.Info("No profiling")
	}

	go initPromHandler(*promPath, *promListen)

	if debugLevel > 10 {
		logger.Info("Prometheus http listener started", "*promListen", *promListen, "*promPath", *promPath)
	}

	// Main setup complete
	//---------------------------------------

	// Real work stuff starts here

	var debugLevels = icmpengine.DebugLevelsT{
		IE: *di,
		S:  *ds,
		R:  *dr,
		E:  *de,
		P:  *dp,
	}

	doneAll := make(chan struct{}, 2)
	ie := icmpengine.NewFullConfig(logger, doneAll, *readDeadline, false, *r4, *r6, *splayReceivers, debugLevels, false)
	ie.Start()
	wg := new(sync.WaitGroup)
	wg.Add(1)
	if debugLevel > 100 {
		logger.Info("main go ie.Run(wg)")
	}
	go ie.Run(wg)

	ips := strings.Split(*dest, ",")
	timeouts := strings.Split(*destTimeout, ",")

	if len(ips) != len(timeouts) {
		log.Fatalf("dest len(ips):%d != destTimeout len(timeouts):%d", len(ips), len(timeouts))
	}

	var timeoutDurations []time.Duration
	for _, timeout := range timeouts {
		timeoutDuration, err := time.ParseDuration(timeout)
		if err != nil {
			log.Fatalf("time.ParseDuration(timeout:%s) err:%v", timeout, err)
		}
		timeoutDurations = append(timeoutDurations, timeoutDuration)
	}

	// var ips []string = []string{"127.0.0.1", "::1"}
	// var ips []string
	// ips = []string{"127.0.0.1", "::1"}
	// if len(*ip) > 0 {
	// 	ips = []string{*ip}
	// 	if debugLevel > 10 {
	// 		logger.Info(fmt.Sprintf("ips now:%s", ips))
	// 	}
	// } else {
	//	ips = []string{"127.0.0.1", "::1"}
	// 	//var ips []string = []string{"::1"}
	// 	//var ips []string = []string{"127.0.0.1"}
	// }

	sCh := make(chan icmpengine.PingerResults, len(ips))
	pwg := new(sync.WaitGroup)
	pDone := make(chan struct{}, 2)

	if debugLevel > 10 {
		logger.Info(fmt.Sprintf("main \tips:%s", ips))
	}
	for i, ip := range ips {

		if debugLevel > 10 {
			logger.Info(fmt.Sprintf("main \ti:%d\tip:[%s]\tblocking:%t", i, ip, *blocking))
		}

		destNetAddr, err := netip.ParseAddr(ip)
		if err != nil {
			log.Fatal("netip.ParseAddr(ip) err:", err)
		}

		if debugLevel > 10 {
			logger.Info(fmt.Sprintf("main starting ie.Pinger, index:%d\tip:[%s]\tcount:%d\tinterval:%s", i, destNetAddr.String(), *count, (*interval).String()))
		}
		if *blocking {
			r := ie.Pinger(destNetAddr, timeoutDurations[i], icmpengine.Sequence(*count), *interval, true, pDone)

			if debugLevel > 10 {
				ie.Log.Info(fmt.Sprintf("main:[%s] \tsuccesses:%d \tfailures:%d \tooo:%d \tcount:%d", r.IP.String(), r.Successes, r.Failures, r.OutOfOrder, r.Count))
				ie.Log.Info(fmt.Sprintf("main:[%s] \tmin:%s \tmax:%s \tmean:%s \tsum:%s \tPingerDuration:%s", r.IP.String(), r.Min.String(), r.Max.String(), r.Mean.String(), r.Sum.String(), r.PingerDuration.String()))
				//ie.Log.Info(fmt.Sprintf("icmpengine main:%s \tmin:%s \tmax:%s \tmean:%s \tvariance:%s \tsum:%s \tPingerDuration:%s", r.IP.String(), r.Min.String(), r.Max.String(), r.Mean.String(), r.Variance.String(), r.Sum.String(), r.PingerDuration.String()))
			}
		} else {
			pwg.Add(1)
			go ie.PingerWithStatsChannel(destNetAddr, timeoutDurations[i], icmpengine.Sequence(*count), *interval, true, pDone, pwg, sCh)
		}
	}

	if !*blocking {
		for i := range ips {
			r := <-sCh
			if debugLevel > 10 {
				logger.Info(fmt.Sprintf("Recieved on channel count:%d\tr.mean:%s", i, r.Mean.String()))
			}
			if debugLevel > 10 {
				ie.Log.Info(fmt.Sprintf("icmpengine main:%s \tsuccesses:%d \tfailures:%d \tooo:%d \tcount:%d", r.IP.String(), r.Successes, r.Failures, r.OutOfOrder, r.Count))
				ie.Log.Info(fmt.Sprintf("icmpengine main:%s \tmin:%s \tmax:%s \tmean:%s \tsum:%s \tPingerDuration:%s", r.IP.String(), r.Min.String(), r.Max.String(), r.Mean.String(), r.Sum.String(), r.PingerDuration.String()))
				//ie.Log.Info(fmt.Sprintf("icmpengine main:%s \tmin:%s \tmax:%s \tmean:%s \tvariance:%s \tsum:%s \tPingerDuration:%s", r.IP.String(), r.Min.String(), r.Max.String(), r.Mean.String(), r.Variance.String(), r.Sum.String(), r.PingerDuration.String()))
			}
			if debugLevel > 100 {
				ie.Log.Info(fmt.Sprintf("icmpengine main:%s \tr.RTTs:", r.RTTs))
			}
		}
	}

	if debugLevel > 10 {
		logger.Info("main pwg.Wait")
	}
	pwg.Wait()

	if debugLevel > 10 {
		logger.Info("main pwg.Wait complete.  Stopping ICMPEngine")
	}

	doneAll <- struct{}{}

	if debugLevel > 100 {
		logger.Info("main wg.Wait")
	}
	wg.Wait()

	if debugLevel > 100 {
		logger.Info("Completed.  Bye bye")
	}
}

// initSignalHandler sets up signal handling for the process, and
// will call cancel() when recieved
func initSignalHandler(cancel context.CancelFunc) {
	c := make(chan os.Signal, signalChannelSize)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c
	log.Printf("Signal caught, closing application")
	cancel()

	log.Printf("Signal caught, sleeping to allow goroutines to close")
	time.Sleep(cancelSleepTime)

	log.Printf("Sleep complete, goodbye! exit(0)")

	os.Exit(0)
}

// initPromHandler starts the prom handler with error checking
func initPromHandler(promPath string, promListen string) {
	// https: //pkg.go.dev/github.com/prometheus/client_golang/prometheus/promhttp?tab=doc#HandlerOpts
	http.Handle(promPath, promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			EnableOpenMetrics:   promEnableOpenMetrics,
			MaxRequestsInFlight: promMaxRequestsInFlight,
		},
	))
	go func() {
		err := http.ListenAndServe(promListen, nil)
		if err != nil {
			log.Fatal("prometheus error", err)
		}
	}()
}
