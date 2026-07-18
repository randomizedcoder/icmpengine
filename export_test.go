package icmpengine

import (
	"net/netip"
	"time"
)

// SetResponder installs a test-only simulated responder used by the deterministic
// (synctest) tests. In fake-success mode the engine delivers a success after the
// returned rtt when respond is true and rtt is within the ping's timeout;
// otherwise the ping times out. Install it before Start. Passing nil clears it.
func (e *Engine) SetResponder(fn func(addr netip.Addr, seq int) (rtt time.Duration, respond bool)) {
	if fn == nil {
		e.responder = nil
		return
	}
	e.responder = func(addr netip.Addr, s sequence) (time.Duration, bool) {
		return fn(addr, int(s))
	}
}
