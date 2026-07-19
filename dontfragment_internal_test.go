//go:build linux

package icmpengine

import (
	"context"
	"testing"

	"golang.org/x/sys/unix"
)

// TestApplyDontFragmentSetsSockopt is a white-box check that WithDontFragment
// actually sets IP_MTU_DISCOVER=IP_PMTUDISC_DO on the IPv4 socket.
func TestApplyDontFragmentSetsSockopt(t *testing.T) {
	eng, err := New(WithLogger(nil), WithDontFragment(true))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Skipf("non-privileged ICMP unavailable: %v", err)
	}
	defer func() { _ = eng.Close() }()

	rc, err := socketRawConn(eng.sockets[proto4], proto4)
	if err != nil {
		t.Fatalf("socketRawConn: %v", err)
	}
	var got int
	var gerr error
	if cerr := rc.Control(func(fd uintptr) {
		got, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
	}); cerr != nil {
		t.Fatalf("control: %v", cerr)
	}
	if gerr != nil {
		t.Fatalf("getsockopt: %v", gerr)
	}
	if got != unix.IP_PMTUDISC_DO {
		t.Fatalf("IP_MTU_DISCOVER = %d, want %d (IP_PMTUDISC_DO)", got, unix.IP_PMTUDISC_DO)
	}
}
