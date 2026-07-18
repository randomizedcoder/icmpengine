package icmpengine

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	// Timeouts-in-a-row (tiar) thresholds and multipliers: the receiver backs
	// off its socket read deadline after repeated idle timeouts to reduce
	// syscall thrashing while still noticing shutdown reasonably quickly.
	tiarLow    = 5
	tiarMedium = 10
	tiarHigh   = 20

	multiLow    = 2
	multiMedium = 10
	multiHigh   = 20
)

// bufPool recycles receive buffers to reduce GC pressure.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, receiveBufferMax)
		return &b
	},
}

// timeoutsInARowCalculator returns the read-deadline multiplier for a number of
// consecutive timeouts, using the package tiar constants.
func timeoutsInARowCalculator(timeoutsInARow int) (multiplier float64) {
	return tiarCalculator(timeoutsInARow, tiarLow, tiarMedium, tiarHigh, multiLow, multiMedium, multiHigh)
}

// tiarCalculator returns the multiplier for a number of consecutive timeouts
// against the given thresholds. Separated out so it can be unit tested.
func tiarCalculator(tiar int, low int, medium int, high int, mLow float64, mMedium float64, mHigh float64) (multiplier float64) {
	multiplier = 1
	switch {
	case tiar >= high:
		multiplier = mHigh
	case tiar >= medium:
		multiplier = mMedium
	case tiar >= low:
		multiplier = mLow
	}
	return multiplier
}

// receiver reads ICMP echo replies from one socket, matches them to outstanding
// pings, and forwards the round-trip time to the waiting Ping call. It runs
// until the engine context is canceled. A blocking ReadFrom is bounded by a
// read deadline (backed off via the tiar table) so cancellation is observed.
func (e *Engine) receiver(proto protocol, index int, socket socketReader) {
	defer e.receiversWG.Done()

	e.logger.Debug("receiver started", "proto", proto, "index", index)

	for timeoutsInARow := 0; ; {
		select {
		case <-e.ctx.Done():
			return
		default:
		}

		buf := bufPool.Get().(*[]byte)

		readDeadline := time.Duration(float64(e.readDeadline) * timeoutsInARowCalculator(timeoutsInARow))
		_ = socket.SetReadDeadline(time.Now().Add(readDeadline))

		n, peer, err := socket.ReadFrom(*buf)
		receiveTime := time.Now()

		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				timeoutsInARow++
			} else {
				bufPool.Put(buf)
				if e.ctx.Err() != nil {
					// Expected: the socket was closed as part of shutdown.
					return
				}
				// A genuine, unexpected read error: record it and trigger a
				// graceful engine shutdown instead of killing the process.
				e.setErr(fmt.Errorf("icmpengine: receiver proto=%d index=%d read: %w", proto, index, err))
				e.logger.Error("receiver read error, shutting engine down", "proto", proto, "index", index, "err", err)
				e.cancel()
				return
			}
		} else {
			timeoutsInARow = 0
		}

		if n > 0 {
			e.handleReply((*buf)[:n], peer, receiveTime, proto, index)
		}
		bufPool.Put(buf)
	}
}

// socketReader is the subset of *icmp.PacketConn the receiver needs; it also
// allows the receiver loop to be exercised without a real socket.
type socketReader interface {
	SetReadDeadline(t time.Time) error
	ReadFrom(b []byte) (int, net.Addr, error)
}

// handleReply parses a received datagram, matches it to an outstanding ping,
// and forwards a pingSuccess to the waiting Ping call.
func (e *Engine) handleReply(buf []byte, peer net.Addr, receiveTime time.Time, proto protocol, index int) {
	echoReply, err := ParseICMPEchoReply(buf)
	if err != nil {
		e.logger.Debug("parse reply failed", "proto", proto, "index", index, "err", err)
		return
	}

	host, _, err := net.SplitHostPort(peer.String())
	if err != nil {
		host = peer.String()
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		e.logger.Debug("unparseable reply peer", "proto", proto, "index", index, "peer", peer.String())
		return
	}
	seq := sequence(echoReply.Seq)

	e.mu.Lock()
	p, ok := e.queue.remove(ip, seq)
	if !ok {
		e.mu.Unlock()
		e.logger.Debug("reply for unknown ping", "ip", ip, "seq", seq)
		return
	}
	ch := e.successChs[ip]
	e.mu.Unlock()

	if ch != nil {
		// ch is buffered to the ping's packet count and each sequence resolves
		// at most once, so this never blocks. If the Ping already returned the
		// channel is orphaned and the send is simply discarded by the GC.
		ch <- pingSuccess{
			Seq:      seq,
			Send:     p.send,
			Received: receiveTime,
			RTT:      receiveTime.Sub(p.send),
		}
	}
}
