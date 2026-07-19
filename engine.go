// Package icmpengine sends non-privileged ICMP echo requests and receives the
// replies concurrently, without blocking on per-packet timeouts. It is designed
// to be embedded in other Go programs.
//
// Non-privileged ICMP uses IPPROTO_ICMP sockets (see
// https://lwn.net/Articles/422330/). On Linux this requires the ping group
// range sysctl to include the running user's gid, e.g.:
//
//	sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
//
// Typical use:
//
//	eng, err := icmpengine.New(icmpengine.WithLogger(logger))
//	if err != nil { ... }
//	if err := eng.Start(ctx); err != nil { ... }
//	defer eng.Close()
//	res, err := eng.Ping(ctx, netip.MustParseAddr("8.8.8.8"), 10, 100*time.Millisecond)
package icmpengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
)

// Sentinel errors returned by the engine.
var (
	// ErrNotStarted is returned by Ping when the engine has not been Started
	// (or has already been Closed).
	ErrNotStarted = errors.New("icmpengine: engine not started")
	// ErrAlreadyStarted is returned by Start when called more than once.
	ErrAlreadyStarted = errors.New("icmpengine: engine already started")
	// ErrCountRange is returned by Ping when count is outside [0, 65535]
	// (ICMP sequence numbers are 16 bits).
	ErrCountRange = errors.New("icmpengine: count out of range [0,65535]")
	// ErrDuplicatePing is returned by Ping when another Ping to the same
	// address is already in flight on this engine.
	ErrDuplicatePing = errors.New("icmpengine: address already being pinged")
	// ErrInvalidAddr is returned by Ping when the destination address is not
	// a valid IPv4 or IPv6 address.
	ErrInvalidAddr = errors.New("icmpengine: invalid destination address")
	// ErrTimeoutRange is returned by Ping when a PingTimeout value is negative.
	ErrTimeoutRange = errors.New("icmpengine: ping timeout must be >= 0")
)

// maxSequence is the largest ICMP sequence number (16 bits).
const maxSequence = 1<<16 - 1

// Internal defaults, previously exported *Cst constants.
const (
	defaultReceivers4  = 2
	defaultReceivers6  = 2
	openSocketsRetries = 2
	receiveBufferMax   = 200
)

type sequence uint16

// protocol is the internal IP-version selector: 4 for IPv4, 6 for IPv6.
type protocol uint8

const (
	proto4 protocol = 4
	proto6 protocol = 6
)

// config holds the values assembled from the Option functions passed to New.
type config struct {
	logger       *slog.Logger
	timeout      time.Duration
	readDeadline time.Duration
	receivers4   int
	receivers6   int
	splay        bool
	fakeSuccess  bool
	hackSysctl   bool
	backend      Backend
}

// Option configures an Engine created by New.
type Option func(*config)

// WithLogger sets the structured logger. A nil logger (the default) discards
// all log output.
func WithLogger(l *slog.Logger) Option { return func(c *config) { c.logger = l } }

// WithTimeout sets how long to wait for an echo reply before a ping is counted
// as a failure. Defaults to 1s.
func WithTimeout(d time.Duration) Option { return func(c *config) { c.timeout = d } }

// WithReadDeadline sets the receiver socket read deadline. It bounds how quickly
// receivers notice Close/cancellation; it is not a per-ping timeout. Defaults to 1s.
func WithReadDeadline(d time.Duration) Option { return func(c *config) { c.readDeadline = d } }

// WithReceivers sets the number of receiver goroutines per protocol. Defaults to 2 and 2.
func WithReceivers(v4, v6 int) Option {
	return func(c *config) { c.receivers4, c.receivers6 = v4, v6 }
}

// WithSplayReceivers staggers receiver startup over the read deadline instead of
// starting them all at once. Defaults to false.
func WithSplayReceivers(b bool) Option { return func(c *config) { c.splay = b } }

// WithFakeSuccess makes the engine synthesize successful replies without opening
// sockets or sending packets. Intended for testing only.
func WithFakeSuccess(b bool) Option { return func(c *config) { c.fakeSuccess = b } }

// WithHackSysctl allows the engine, when running as root, to run
// "sysctl -w net.ipv4.ping_group_range=0 2147483647" if opening sockets fails.
// Off by default; opt in only if you understand the implication.
func WithHackSysctl(b bool) Option { return func(c *config) { c.hackSysctl = b } }

// WithExpiryBackend selects the data structure used to track outstanding pings.
// Defaults to BackendDaryHeap (the fastest in benchmarks); see docs/backends.md.
func WithExpiryBackend(b Backend) Option { return func(c *config) { c.backend = b } }

// Engine sends ICMP echo requests and matches them to replies. Create one with
// New, Start it, call Ping/PingAll, then Close it. An Engine is safe for
// concurrent use by multiple goroutines. It implements io.Closer.
type Engine struct {
	logger       *slog.Logger
	timeout      time.Duration
	readDeadline time.Duration
	protocols    []protocol
	receivers    map[protocol]int
	splay        bool
	fakeSuccess  bool
	hackSysctl   bool
	pid          int
	eid          int

	// responder, when non-nil, makes the fake-success path deliver a simulated
	// RTT (or a drop/timeout) instead of an instant success. It is a test-only
	// hook installed via export_test.go before Start, so it needs no locking.
	responder func(netip.Addr, sequence) (time.Duration, bool)

	startOnce sync.Once
	closeOnce sync.Once
	closeErr  error

	// ctx/cancel are set by Start and drive shutdown of all goroutines.
	ctx    context.Context
	cancel context.CancelFunc

	// mu guards every field below. A single mutex is intentional: sharding
	// per-address state is possible (and the -pprof mutex profile would show
	// if it is ever needed) but the global "soonest expiry" invariant does not
	// shard cleanly, so it is deliberately left as future work.
	mu          sync.Mutex
	started     bool
	sockets     map[protocol]*icmp.PacketConn
	socketsOpen bool
	queue       expiryTracker
	successChs  map[netip.Addr]chan pingSuccess
	expiredChs  map[netip.Addr]chan pingExpired
	expirerRun  bool

	receiversWG sync.WaitGroup
	expirerWG   sync.WaitGroup
	pingersWG   sync.WaitGroup

	errMu sync.Mutex
	bgErr error // first fatal background (receiver) error
}

var _ io.Closer = (*Engine)(nil)

// New creates an Engine from the given options. It validates configuration and
// returns an error instead of terminating the process. New does not open
// sockets or start goroutines; call Start for that.
func New(opts ...Option) (*Engine, error) {
	c := config{
		timeout:      time.Second,
		readDeadline: time.Second,
		receivers4:   defaultReceivers4,
		receivers6:   defaultReceivers6,
		backend:      BackendDaryHeap, // fastest across the benchmarks; see docs/backends.md
	}
	for _, o := range opts {
		o(&c)
	}

	if c.timeout <= 0 {
		return nil, fmt.Errorf("icmpengine: timeout must be > 0, got %s", c.timeout)
	}
	if c.readDeadline <= 0 {
		return nil, fmt.Errorf("icmpengine: read deadline must be > 0, got %s", c.readDeadline)
	}
	if c.receivers4 < 0 || c.receivers6 < 0 {
		return nil, fmt.Errorf("icmpengine: receiver counts must be >= 0, got v4=%d v6=%d", c.receivers4, c.receivers6)
	}
	if !c.fakeSuccess && c.receivers4+c.receivers6 < 1 {
		return nil, errors.New("icmpengine: at least one receiver is required")
	}

	e := &Engine{
		logger:       loggerOrDiscard(c.logger),
		timeout:      c.timeout,
		readDeadline: c.readDeadline,
		protocols:    []protocol{proto4, proto6},
		receivers:    map[protocol]int{proto4: c.receivers4, proto6: c.receivers6},
		splay:        c.splay,
		fakeSuccess:  c.fakeSuccess,
		hackSysctl:   c.hackSysctl,
		pid:          os.Getpid() & 0xffff,
		eid:          os.Geteuid(),
		sockets:      make(map[protocol]*icmp.PacketConn),
		queue:        newExpiryTracker(c.backend),
		successChs:   make(map[netip.Addr]chan pingSuccess),
		expiredChs:   make(map[netip.Addr]chan pingExpired),
	}
	return e, nil
}

// loggerOrDiscard returns l, or a logger that discards everything if l is nil.
func loggerOrDiscard(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.DiscardHandler)
}

// Start opens the ICMP sockets and launches the receiver goroutines. The
// provided context governs the engine's lifetime: canceling it (or calling
// Close) shuts everything down. Start may be called only once.
func (e *Engine) Start(ctx context.Context) error {
	err := ErrAlreadyStarted
	e.startOnce.Do(func() {
		e.ctx, e.cancel = context.WithCancel(ctx)

		if e.fakeSuccess {
			// No sockets or receivers: the expirer synthesizes successes.
			e.mu.Lock()
			e.started = true
			e.mu.Unlock()
			e.logger.Debug("engine started in fake-success mode")
			err = nil
			return
		}

		if oerr := e.openSockets(); oerr != nil {
			err = oerr
			return
		}
		e.startReceivers()

		e.mu.Lock()
		e.started = true
		e.mu.Unlock()
		e.logger.Debug("engine started")
		err = nil
	})
	return err
}

// startReceivers launches the receiver goroutines, optionally splaying their
// start times across the read deadline.
func (e *Engine) startReceivers() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, p := range e.protocols {
		socket := e.sockets[p]
		for r := 0; r < e.receivers[p]; r++ {
			e.receiversWG.Add(1)
			go e.receiver(p, r, socket)
			if e.splay && e.receivers[p] > 0 {
				splay := time.Duration(float64(e.readDeadline) / float64(e.receivers[p]))
				select {
				case <-time.After(splay):
				case <-e.ctx.Done():
					return
				}
			}
		}
	}
}

// Close shuts the engine down: it cancels the engine context, waits for all
// in-flight pings and background goroutines to finish, and closes the sockets.
// Close is idempotent and returns the first fatal background error, if any.
func (e *Engine) Close() error {
	e.closeOnce.Do(func() {
		if e.cancel == nil {
			// Start was never called.
			return
		}
		// Unblock any receiver parked in ReadFrom so shutdown is prompt rather
		// than waiting up to a full (backed-off) read deadline.
		e.mu.Lock()
		for _, s := range e.sockets {
			_ = s.SetReadDeadline(time.Now())
		}
		e.mu.Unlock()

		e.cancel()

		e.pingersWG.Wait()
		e.expirerWG.Wait()
		e.receiversWG.Wait()

		if cerr := e.closeSockets(); cerr != nil {
			e.logger.Warn("closing sockets", "err", cerr)
		}

		e.mu.Lock()
		e.started = false
		e.mu.Unlock()

		e.closeErr = e.Err()
		e.logger.Debug("engine closed")
	})
	return e.closeErr
}

// Err returns the first fatal error observed by a background (receiver)
// goroutine, or nil. A non-nil Err means the engine has begun shutting itself
// down.
func (e *Engine) Err() error {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	return e.bgErr
}

// setErr records the first fatal background error.
func (e *Engine) setErr(err error) {
	e.errMu.Lock()
	if e.bgErr == nil {
		e.bgErr = err
	}
	e.errMu.Unlock()
}

// isStarted reports whether the engine is currently started.
func (e *Engine) isStarted() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.started
}

// protocolFor returns the internal protocol selector for addr.
func protocolFor(addr netip.Addr) (protocol, bool) {
	switch {
	case addr.Is4():
		return proto4, true
	case addr.Is6():
		return proto6, true
	default:
		return 0, false
	}
}
