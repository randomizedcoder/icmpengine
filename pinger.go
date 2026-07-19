package icmpengine

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Result holds the aggregated statistics for a single Ping call.
type Result struct {
	IP         netip.Addr
	Successes  int
	Failures   int
	OutOfOrder int
	RTTs       []time.Duration
	Count      int
	Min        time.Duration
	Max        time.Duration
	Mean       time.Duration
	Variance   time.Duration
	Sum        time.Duration
	// Duration is the wall-clock time the Ping call took.
	Duration time.Duration
}

// pingSuccess is passed from a receiver (or the fake-success expirer) to a Ping.
type pingSuccess struct {
	Seq      sequence
	Send     time.Time
	Received time.Time
	RTT      time.Duration
}

// pingExpired is passed from the expirer to a Ping on timeout.
type pingExpired struct {
	Seq  sequence
	Send time.Time
}

// pingConfig holds the per-call options assembled from PingOption values.
type pingConfig struct {
	sortRTTs    bool
	dropProb    float64
	timeout     time.Duration // 0 = use the engine default
	payloadSize int           // ICMP data bytes after the 8-byte header
}

// PingOption customizes a single Ping call.
type PingOption func(*pingConfig)

// SortRTTs sorts Result.RTTs ascending before returning.
func SortRTTs() PingOption { return func(c *pingConfig) { c.sortRTTs = true } }

// DropProbability fakes packet loss with the given probability in [0,1] by not
// actually sending the echo request. Intended for testing only.
func DropProbability(p float64) PingOption { return func(c *pingConfig) { c.dropProb = p } }

// PingTimeout overrides the engine's default timeout for this Ping call, so
// different destinations can wait different amounts of time before a packet is
// counted as a failure (e.g. 10ms on a LAN, hours for an interplanetary link).
// A zero value keeps the engine default; a negative value is rejected.
func PingTimeout(d time.Duration) PingOption { return func(c *pingConfig) { c.timeout = d } }

// PayloadSize sets the number of ICMP data bytes appended after the 8-byte ICMP
// header, like ping's -s option (so PayloadSize(56) yields a 64-byte ICMP
// message). The kernel adds the IP header on top. A value of 0 (the default)
// sends a bare echo request. Values outside [0, 65500] are rejected by Ping.
func PayloadSize(n int) PingOption { return func(c *pingConfig) { c.payloadSize = n } }

// Target describes one destination for PingAll.
type Target struct {
	Addr     netip.Addr
	Count    int
	Interval time.Duration
	Options  []PingOption
}

// Ping sends count echo requests to addr, interval apart, and returns aggregated
// statistics. It blocks until every packet has been answered or timed out, or
// until ctx (or the engine) is canceled. On cancellation it returns the partial
// Result gathered so far alongside a non-nil error.
func (e *Engine) Ping(ctx context.Context, addr netip.Addr, count int, interval time.Duration, opts ...PingOption) (Result, error) {
	if !e.isStarted() {
		return Result{}, ErrNotStarted
	}
	if count < 0 || count > maxSequence {
		return Result{}, ErrCountRange
	}
	proto, ok := protocolFor(addr)
	if !ok {
		return Result{}, fmt.Errorf("%w: %s", ErrInvalidAddr, addr)
	}

	var pc pingConfig
	for _, o := range opts {
		o(&pc)
	}
	if pc.timeout < 0 {
		return Result{}, ErrTimeoutRange
	}
	if pc.payloadSize < 0 || pc.payloadSize > maxPayloadSize {
		return Result{}, ErrPayloadSizeRange
	}
	timeout := e.timeout
	if pc.timeout > 0 {
		timeout = pc.timeout
	}

	// Cancel this ping when either the caller's ctx or the engine shuts down.
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Also cancel this ping when the engine itself shuts down. AfterFunc does
	// not create a context, so contextcheck's warning does not apply here.
	defer context.AfterFunc(e.ctx, cancel)() //nolint:contextcheck

	socket, successCh, expiredCh, cleanup, err := e.registerPing(addr, proto, count)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()

	result := Result{IP: addr, RTTs: make([]time.Duration, count)}
	startTime := time.Now()
	canceled := false

	for i := 0; i < count; i++ {
		loopStart := time.Now()
		drop := pc.dropProb > 0 && fakeDrop(pc.dropProb)

		sent, serr := e.sendPacket(addr, proto, socket, i, drop, timeout, pc.payloadSize)
		if serr != nil {
			return finishResult(result, pc, startTime), serr
		}
		if !sent {
			canceled = true
			break
		}

		// Wait for this packet to resolve (reply, timeout, or cancellation).
		select {
		case ps := <-successCh:
			recordSuccess(&result, ps, sequence(i))
		case <-expiredCh:
			result.Failures++
		case <-pctx.Done():
			canceled = true
		}
		if canceled {
			break
		}

		if i+1 < count && !sleepInterval(pctx, interval-time.Since(loopStart)) {
			canceled = true
			break
		}
	}

	result = finishResult(result, pc, startTime)
	if canceled {
		if e.ctx.Err() != nil {
			return result, fmt.Errorf("icmpengine: engine closed: %w", e.ctx.Err())
		}
		return result, context.Cause(ctx)
	}
	return result, nil
}

// registerPing wires up the per-address result channels and marks the ping
// active. The returned cleanup must be deferred by the caller.
func (e *Engine) registerPing(addr netip.Addr, proto protocol, count int) (socket *icmp.PacketConn, successCh chan pingSuccess, expiredCh chan pingExpired, cleanup func(), err error) {
	// Buffered to count so receiver/expirer never block sending results.
	successCh = make(chan pingSuccess, count)
	expiredCh = make(chan pingExpired, count)

	e.mu.Lock()
	if e.ctx.Err() != nil {
		e.mu.Unlock()
		return nil, nil, nil, nil, ErrNotStarted
	}
	if _, dup := e.successChs[addr]; dup {
		e.mu.Unlock()
		return nil, nil, nil, nil, fmt.Errorf("%w: %s", ErrDuplicatePing, addr)
	}
	socket = e.sockets[proto]
	e.successChs[addr] = successCh
	e.expiredChs[addr] = expiredCh
	e.pingersWG.Add(1)
	e.mu.Unlock()

	cleanup = func() {
		e.mu.Lock()
		delete(e.successChs, addr)
		delete(e.expiredChs, addr)
		e.queue.deleteAddr(addr)
		e.mu.Unlock()
		e.pingersWG.Done()
	}
	return socket, successCh, expiredCh, cleanup, nil
}

// sendPacket registers echo request seq i in the expiry queue (expiring after
// timeout) and writes it to the wire, unless faking success or a drop. It
// returns false if the engine has shut down and no packet was registered.
func (e *Engine) sendPacket(addr netip.Addr, proto protocol, socket *icmp.PacketConn, i int, drop bool, timeout time.Duration, payloadSize int) (sent bool, err error) {
	seq := sequence(i)

	// Test-only simulation: when a responder is installed, the fake-success path
	// delivers a simulated RTT after a timer rather than an instant success. A
	// simulated reply that arrives within the timeout is a success; anything
	// else (no response, or an RTT past the timeout) falls through to a timeout.
	simulateSuccess, simRTT := false, time.Duration(0)
	if e.fakeSuccess && e.responder != nil {
		rtt, respond := e.responder(addr, seq)
		drop = true // the expirer only ever times these out; success comes via timer
		simulateSuccess = respond && rtt < timeout
		simRTT = rtt
	}

	var (
		wb  []byte
		dst *net.UDPAddr
	)
	if !e.fakeSuccess && !drop {
		wb, err = buildICMPMessage(e.pid, seq, proto, payloadSize).Marshal(nil)
		if err != nil {
			return false, fmt.Errorf("icmpengine: marshal echo request: %w", err)
		}
		dst = &net.UDPAddr{IP: net.IP(addr.AsSlice())}
	}

	e.mu.Lock()
	if e.ctx.Err() != nil {
		e.mu.Unlock()
		return false, nil
	}
	send := time.Now()
	e.queue.push(&pending{addr: addr, seq: seq, send: send, expiry: send.Add(timeout), fakeDrop: drop})
	e.ensureExpirer()
	e.mu.Unlock()

	if simulateSuccess {
		e.scheduleFakeSuccess(addr, seq, send, simRTT)
	}

	if !e.fakeSuccess && !drop {
		if werr := writeTo(socket, wb, dst); werr != nil {
			return false, werr
		}
	}
	return true, nil
}

// scheduleFakeSuccess (test-only, responder path) delivers a simulated success
// after rtt of fake time, removing the pending so the expirer will not also
// time it out. If the ping has already finished the send is dropped.
func (e *Engine) scheduleFakeSuccess(addr netip.Addr, seq sequence, send time.Time, rtt time.Duration) {
	time.AfterFunc(rtt, func() {
		e.mu.Lock()
		_, ok := e.queue.remove(addr, seq)
		ch := e.successChs[addr]
		e.mu.Unlock()
		if !ok || ch == nil {
			return
		}
		ch <- pingSuccess{Seq: seq, Send: send, Received: send.Add(rtt), RTT: rtt}
	})
}

// finishResult fills in the derived fields (duration, count, sorted RTTs).
func finishResult(result Result, pc pingConfig, startTime time.Time) Result {
	result.Duration = time.Since(startTime)
	result.Count = result.Successes + result.Failures
	if pc.sortRTTs {
		slices.Sort(result.RTTs)
	}
	return result
}

// sleepInterval waits for d (if positive) or until pctx is done, reporting
// false if pctx was canceled first.
func sleepInterval(pctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-pctx.Done():
		return false
	}
}

// recordSuccess folds one reply into the running statistics using Welford's
// one-pass mean/variance algorithm.
func recordSuccess(result *Result, ps pingSuccess, i sequence) {
	val := ps.RTT
	result.RTTs[i] = val
	result.Sum += val
	if result.Successes == 0 {
		result.Min = val
		result.Max = val
	} else {
		result.Min = min(result.Min, val)
		result.Max = max(result.Max, val)
	}
	result.Successes++
	oldMean := result.Mean
	result.Mean += time.Duration(float64(val-oldMean) / float64(result.Successes))
	result.Variance += time.Duration(((val.Seconds() - oldMean.Seconds()) * (val.Seconds() - result.Mean.Seconds()))) * time.Second
	if ps.Seq != i {
		result.OutOfOrder++
	}
}

// PingAll pings every target concurrently with at most concurrency pings in
// flight at once (concurrency <= 0 means one worker per target). Results are
// returned aligned to targets. It returns the first error encountered, if any;
// per-target partial results are still populated.
func (e *Engine) PingAll(ctx context.Context, concurrency int, targets []Target) ([]Result, error) {
	results := make([]Result, len(targets))
	if len(targets) == 0 {
		return results, nil
	}
	if concurrency <= 0 || concurrency > len(targets) {
		concurrency = len(targets)
	}

	sem := make(chan struct{}, concurrency)
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)
	for i := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			t := targets[i]
			r, err := e.Ping(ctx, t.Addr, t.Count, t.Interval, t.Options...)
			results[i] = r
			if err != nil {
				errOnce.Do(func() { firstErr = err })
			}
		}(i)
	}
	wg.Wait()
	return results, firstErr
}

// fakeDrop reports true with probability dropProb in (0,1].
func fakeDrop(dropProb float64) bool {
	return dropProb > 0 && rand.Float64() >= (1-dropProb)
}

// writeTo sends wb to dst on socket, translating write failures into errors.
func writeTo(socket *icmp.PacketConn, wb []byte, dst *net.UDPAddr) error {
	n, err := socket.WriteTo(wb, dst)
	if err != nil {
		if errors.Is(err, syscall.ENOBUFS) {
			return fmt.Errorf("icmpengine: socket send buffer full (ENOBUFS): %w", err)
		}
		return fmt.Errorf("icmpengine: writing echo request to %s: %w", dst.IP, err)
	}
	if n != len(wb) {
		return fmt.Errorf("icmpengine: short write to %s: wrote %d of %d bytes", dst.IP, n, len(wb))
	}
	return nil
}

// buildICMPMessage builds the icmp.Echo request for the given protocol. When
// payloadSize > 0 it appends that many data bytes after the 8-byte ICMP header.
func buildICMPMessage(id int, seq sequence, proto protocol, payloadSize int) *icmp.Message {
	body := &icmp.Echo{ID: id, Seq: int(seq)}
	if payloadSize > 0 {
		body.Data = makePayload(payloadSize)
	}
	if proto == proto4 {
		return &icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: body}
	}
	return &icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: body}
}

// makePayload returns n data bytes filled with a repeating 0x00..0xff pattern,
// mirroring how iputils ping fills its echo payload.
func makePayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}
