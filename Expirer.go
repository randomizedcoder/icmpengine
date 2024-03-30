package icmpengine

// Expirer holds a sinlge sleep timer

// Socketsider using heap, rather than ordered DLL, which would allow for different timeout values
// https://golang.org/pkg/container/heap/

// Notes
// Currently have a single expirer, but could easily have one per protocol which would provide more parallelism
// The other suggestion is to make a single expiry for a batch of packets, rather than one per packet.
// Both these ideas could help if performance becomes an issue, which currnetly it is not.

import (
	"fmt"
	"time"
)

const (
	EdebugLevel = 111
)

// CheckExpirerIsRunning checks Expirers is running, and starts it if required
// returns if Expirers was started
// CheckExpirerIsRunning assumes the LOCK is already held by Pinger
func (ie *ICMPEngine) CheckExpirerIsRunning() (started bool) {

	ie.debugLog(ie.Expirers.DebugLevel > 100, "CheckExpirerIsRunning() start")

	if ie.Expirers.Running {
		ie.debugLog(ie.Expirers.DebugLevel > 100, "CheckExpirerIsRunning ie.Expirers.Running")
		started = false
		return started
	}

	ie.Expirers.WG.Add(1)
	go ie.ExpirerConfig(ie.Expirers.FakeSuccess)
	ie.Expirers.Running = true

	ie.debugLog(ie.Expirers.DebugLevel > 100, "CheckExpirerIsRunning started")
	started = true

	return started
}

// Expirer tracks the ICMP echo timeouts
// The idea is to just have the single and nearest timer running at any single moment
// The "Config" implies that we can configure the FakeSuccess, which is used for testing
func (ie *ICMPEngine) ExpirerConfig(FakeSuccess bool) {

	ie.debugLog(ie.Expirers.DebugLevel > 100, fmt.Sprintf("Expirer start \t FakeSuccess:%t", FakeSuccess))

	defer ie.Expirers.WG.Done()

	ie.debugLog(ie.Expirers.DebugLevel > 100, "Expirer trying to acquire ie.RLock()")
	ie.RLock()
	doneCh := ie.Expirers.DoneCh
	newSoonestCh := ie.Expirers.NewSoonestCh
	ie.RUnlock()
	ie.debugLog(ie.Expirers.DebugLevel > 100, "Expirer ie.RUnlock()-ed")

	for i, keepLooping := 0, true; keepLooping; i++ {

		ie.debugLog(ie.Expirers.DebugLevel > 100, fmt.Sprintf("Expirer \t i:%d", i))

		select {
		case <-doneCh:
			ie.debugLog(ie.Expirers.DebugLevel > 100, "Expirer received done")
			keepLooping = false
			continue
		default:
			// non-block
		}

		ie.debugLog(ie.Expirers.DebugLevel > 100,
			fmt.Sprintf("Expirer trying to acquire ie.Lock() to check len\t i:%d", i))

		ie.Lock() // <-------------------------- LOCK!!
		if ie.Pingers.ExpiresBtree.Len() == 0 {
			ie.Expirers.Running = false
			ie.Unlock() // <-------------------- UNLOCK!!

			ie.debugLog(ie.Expirers.DebugLevel > 100,
				"Expirer ie.Unlock(). No more elements in expires list, len == 0.  Returning")

			keepLooping = false
			return
		}

		soonestPing, ok := ie.Pingers.ExpiresBtree.Min()
		if !ok {
			ie.debugLog(ie.Expirers.DebugLevel > 100, "Expirer no minimum? returning")
			keepLooping = false
			return
		}

		if FakeSuccess && !soonestPing.FakeDrop {
			ie.debugLog(ie.Expirers.DebugLevel > 100, "Expirer FakeSuccess doing delete")

			ie.Pingers.ExpiresBtree.Delete(soonestPing)
			delete(ie.Pingers.Pings[soonestPing.NetaddrIP], soonestPing.Seq)
			successCh := ie.Pingers.PingersChannels[soonestPing.NetaddrIP].SuccessCh
			ie.Unlock() // <-------------------- UNLOCK!!

			ie.debugLog(ie.Expirers.DebugLevel > 100, "Expirer FakeSuccess ie.Unlock()")

			fakeReceivedTime := time.Now()
			rttDuration := fakeReceivedTime.Sub(soonestPing.SendTime)
			successCh <- PingSuccess{
				Seq:      soonestPing.Seq,
				Send:     soonestPing.SendTime,
				Received: fakeReceivedTime,
				RTT:      rttDuration,
			}
			ie.debugLog(ie.Expirers.DebugLevel > 100,
				fmt.Sprintf("Expirer \t i:%d Sent <- PingSuccess FakeSuccess", i))

			continue
		}
		ie.Unlock() // <------------------------ UNLOCK!!

		sleepDuration := time.Until(soonestPing.ExpiryTime)
		timer := time.NewTimer(sleepDuration)

		ie.debugLog(ie.Expirers.DebugLevel > 100,
			fmt.Sprintf("Expirer \t i:%d going to sleep duration:%s", i, sleepDuration.String()))

		select {
		case <-timer.C:
			ie.debugLog(ie.Expirers.DebugLevel > 100,
				fmt.Sprintf("Expirer wakes up after duration:%s", sleepDuration.String()))

		case exp := <-newSoonestCh:
			ie.debugLog(ie.Expirers.DebugLevel > 100, "Expirer exp := <-newSoonestCh, resetting timer")
			// Reset the timer
			// https://pkg.go.dev/time#Timer.Reset
			if !timer.Stop() {
				<-timer.C
			}
			sleepDuration = time.Until(exp)
			timer.Reset(sleepDuration)

		case <-doneCh:
			ie.debugLog(ie.Expirers.DebugLevel > 100, "Expirer was sleeping, but received done")

			keepLooping = false
			// NO DEFAULT - This is BLOCKING
			//default:
		}

		ie.debugLog(ie.Expirers.DebugLevel > 100, "Expirer woke up, trying to acquire ie.RLock() to check exists")

		ie.RLock() // <-------------------------- READ LOCK!!
		p, exists := ie.Pingers.Pings[soonestPing.NetaddrIP][soonestPing.Seq]
		ie.RUnlock() // <------------------------ READ UNLOCK!!
		if ie.Expirers.DebugLevel > 100 {
			ie.Log.Info(fmt.Sprintf("Expirer ie.RUnlock(), exists:%t", exists))
		}

		// If the key still exists, then the Receiver did NOT get a return packet, so the timeout has expired
		if exists {
			ie.debugLog(ie.Expirers.DebugLevel > 100, fmt.Sprintf("Expirer found expired \t IP:%s \t Seq:%d deleting",
				soonestPing.NetaddrIP.String(), soonestPing.Seq))

			ie.debugLog(ie.Expirers.DebugLevel > 100, "Expirer exists - trying to acquire ie.Lock()")

			ie.Lock() // <----------------------- LOCK!!
			delete(ie.Pingers.Pings[soonestPing.NetaddrIP], soonestPing.Seq)
			ie.Pingers.ExpiresBtree.Delete(p)
			expiredCh := ie.Pingers.PingersChannels[soonestPing.NetaddrIP].ExpiredCh
			ie.Unlock() // <--------------------- UNLOCK!!

			ie.debugLog(ie.Expirers.DebugLevel > 100, "Expirer exists - ie.Unlock()")

			expiredCh <- PingExpired{
				Seq:  soonestPing.Seq,
				Send: soonestPing.SendTime,
			}
			ie.debugLog(ie.Expirers.DebugLevel > 100, fmt.Sprintf("Expirer \t i:%d Sent <- PingExpired", i))

		} else {
			ie.debugLog(ie.Expirers.DebugLevel > 100,
				"Expirer expiry no longer exists, so we must have received a response.  Excellent.")
		}
	}

	ie.debugLog(ie.Expirers.DebugLevel > 100,
		"Expirer - trying to acquire ie.Lock() to ie.Expirers.Running = false, Defer unlock")

	ie.Lock()
	defer ie.Unlock()
	len := ie.Pingers.ExpiresBtree.Len()
	ie.Expirers.Running = false

	ie.debugLog(ie.Expirers.DebugLevel > 100, fmt.Sprintf("Expirer len:%d ie.ExpirerRunning = false.  Expirer complete. defer ie.Unlock()", len))
}
