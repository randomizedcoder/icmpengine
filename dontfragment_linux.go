//go:build linux

package icmpengine

// Don't-Fragment support for non-privileged ICMP sockets on Linux. The DF bit
// is a socket option, not a raw IP-header field, so it can be set without
// CAP_NET_RAW by enabling path-MTU discovery (IP_MTU_DISCOVER = IP_PMTUDISC_DO),
// the same mechanism `ping -M do` uses on datagram sockets.

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/icmp"
	"golang.org/x/sys/unix"
)

// applyDontFragment enables path-MTU discovery (setting the DF bit) on the
// socket when on is true. It is a no-op when on is false.
func applyDontFragment(sock *icmp.PacketConn, p protocol, on bool) error {
	if !on {
		return nil
	}
	rc, err := socketRawConn(sock, p)
	if err != nil {
		return err
	}
	var opErr error
	if cerr := rc.Control(func(fd uintptr) {
		if p == proto4 {
			opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
		} else {
			opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
		}
	}); cerr != nil {
		return fmt.Errorf("icmpengine: accessing socket for dont-fragment: %w", cerr)
	}
	if opErr != nil {
		return fmt.Errorf("icmpengine: setting dont-fragment (mtu discover): %w", opErr)
	}
	return nil
}

// socketRawConn reaches the syscall.RawConn behind the icmp socket via the
// net.PacketConn promoted by the ipv4/ipv6 wrapper.
func socketRawConn(sock *icmp.PacketConn, p protocol) (syscall.RawConn, error) {
	var pc net.PacketConn
	if p == proto4 {
		pc = sock.IPv4PacketConn().PacketConn
	} else {
		pc = sock.IPv6PacketConn().PacketConn
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("icmpengine: underlying socket %T does not implement syscall.Conn", pc)
	}
	return sc.SyscallConn()
}
