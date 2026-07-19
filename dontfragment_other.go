//go:build !linux

package icmpengine

import "golang.org/x/net/icmp"

// applyDontFragment reports that the Don't-Fragment bit cannot be set on
// non-privileged sockets on this platform. It is a no-op (and returns nil) when
// dont-fragment was not requested.
func applyDontFragment(sock *icmp.PacketConn, p protocol, on bool) error {
	if !on {
		return nil
	}
	return ErrDontFragmentUnsupported
}
