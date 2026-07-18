package icmpengine

import "time"

// The expirer keeps a single sleep timer for the soonest-expiring outstanding
// ping. It is started lazily by Ping (via ensureExpirer) and stops itself once
// the queue drains, so it only runs while pings are in flight.
//
// A single expirer is sufficient for current workloads. Per-protocol expirers
// (or one expiry per batch) would add parallelism if that ever becomes a
// bottleneck.

// ensureExpirer starts the expirer goroutine if it is not already running.
// It must be called with e.mu held (Ping holds it while pushing a pending).
func (e *Engine) ensureExpirer() {
	if e.expirerRun {
		return
	}
	e.expirerRun = true
	e.expirerWG.Add(1)
	go e.expirer()
}

// expirer waits for the soonest outstanding ping to expire, then reports it as
// a timeout unless a reply removed it first. In fake-success mode it instead
// synthesizes an immediate success for every non-dropped ping.
func (e *Engine) expirer() {
	defer e.expirerWG.Done()
	e.logger.Debug("expirer started", "fakeSuccess", e.fakeSuccess)

	for {
		select {
		case <-e.ctx.Done():
			return
		default:
		}

		e.mu.Lock()
		p, ok := e.queue.peek()
		if !ok {
			// Nothing outstanding: stop, so Ping re-arms us on the next push.
			e.expirerRun = false
			e.mu.Unlock()
			e.logger.Debug("expirer idle, stopping")
			return
		}

		if e.fakeSuccess && !p.fakeDrop {
			e.queue.remove(p.addr, p.seq)
			ch := e.successChs[p.addr]
			e.mu.Unlock()

			now := time.Now()
			if ch != nil {
				ch <- pingSuccess{Seq: p.seq, Send: p.send, Received: now, RTT: now.Sub(p.send)}
			}
			continue
		}

		addr, seq, expiry := p.addr, p.seq, p.expiry
		e.mu.Unlock()

		timer := time.NewTimer(time.Until(expiry))
		select {
		case <-timer.C:
		case <-e.ctx.Done():
			timer.Stop()
			return
		}

		e.mu.Lock()
		expired, ok := e.queue.remove(addr, seq)
		if !ok {
			// A reply already removed it: not a timeout.
			e.mu.Unlock()
			continue
		}
		ch := e.expiredChs[addr]
		e.mu.Unlock()

		if ch != nil {
			ch <- pingExpired{Seq: expired.seq, Send: expired.send}
		}
	}
}
