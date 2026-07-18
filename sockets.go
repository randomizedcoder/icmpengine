package icmpengine

// Non-privileged ICMP sockets (IPPROTO_ICMP), see https://lwn.net/Articles/422330/

import (
	"errors"
	"fmt"

	"github.com/go-cmd/cmd"
	"golang.org/x/net/icmp"
)

// networkForProtocol / addressForProtocol give the icmp.ListenPacket arguments.
func networkForProtocol(p protocol) (network, address string) {
	if p == proto4 {
		return "udp4", "0.0.0.0"
	}
	return "udp6", "::"
}

// openSockets opens one non-privileged ICMP socket per protocol. If a listen
// fails and WithHackSysctl was set and the engine is running as root, it tries
// the sysctl workaround once before retrying. It returns an error rather than
// terminating the process.
func (e *Engine) openSockets() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.socketsOpen {
		return nil
	}

	for _, p := range e.protocols {
		network, address := networkForProtocol(p)
		var (
			sock      *icmp.PacketConn
			listenErr error
		)
		for retries := 0; retries < openSocketsRetries; retries++ {
			sock, listenErr = icmp.ListenPacket(network, address)
			if listenErr == nil {
				break
			}
			if e.hackSysctl && e.hackSysctlOnce() {
				continue
			}
			break
		}
		if listenErr != nil {
			// Roll back any sockets already opened.
			for _, op := range e.protocols {
				if s, ok := e.sockets[op]; ok {
					_ = s.Close()
					delete(e.sockets, op)
				}
			}
			return fmt.Errorf("icmpengine: opening %s socket: %w (hint: sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\")", network, listenErr)
		}
		e.sockets[p] = sock
	}

	e.socketsOpen = true
	return nil
}

// closeSockets closes all open sockets. It must be called after the receivers
// have stopped.
func (e *Engine) closeSockets() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.socketsOpen {
		return nil
	}

	var errs []error
	for _, p := range e.protocols {
		if s, ok := e.sockets[p]; ok {
			if err := s.Close(); err != nil {
				errs = append(errs, err)
			}
			delete(e.sockets, p)
		}
	}
	e.socketsOpen = false
	return errors.Join(errs...)
}

// hackSysctlOnce runs "sysctl -w net.ipv4.ping_group_range=0 2147483647" when
// running as root. It reports whether it attempted the change. Assumes the
// engine mutex is held. Requires root (euid 0).
func (e *Engine) hackSysctlOnce() bool {
	if e.eid != 0 {
		return false
	}
	sysctlCmd := cmd.NewCmd(`sysctl`, `-w`, `net.ipv4.ping_group_range=0 2147483647`)
	status := <-sysctlCmd.Start()
	e.logger.Debug("hack sysctl ping_group_range", "exit", status.Exit)
	return true
}
