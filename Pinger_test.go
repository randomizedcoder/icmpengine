package icmpengine

import (
	"net/netip"
	"testing"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// TestFakeDrop verifies the probabilistic drop helper. The 0 and 1 bounds are
// deterministic; the middle is checked against a statistical band.
func TestFakeDrop(t *testing.T) {
	const iterations = 10000

	t.Run("prob_0_never_drops", func(t *testing.T) {
		for i := range iterations {
			if FakeDrop(0) {
				t.Fatalf("FakeDrop(0) returned true on iteration %d, want always false", i)
			}
		}
	})

	t.Run("prob_1_always_drops", func(t *testing.T) {
		for i := range iterations {
			if !FakeDrop(1) {
				t.Fatalf("FakeDrop(1) returned false on iteration %d, want always true", i)
			}
		}
	})

	// Statistical band for intermediate probabilities. Use a generous tolerance
	// so the test is not flaky, matching the fudge-factor style already used in
	// TestPingerFakeDrop.
	for _, prob := range []float64{0.25, 0.5, 0.75} {
		t.Run("prob_band", func(t *testing.T) {
			drops := 0
			for range iterations {
				if FakeDrop(prob) {
					drops++
				}
			}
			got := float64(drops) / float64(iterations)
			const tolerance = 0.05
			if got < prob-tolerance || got > prob+tolerance {
				t.Errorf("FakeDrop(%.2f) dropped %.3f of the time, want within +/-%.2f", prob, got, tolerance)
			}
		})
	}
}

// TestBuildICMPMessage checks the ICMP message type per protocol and that the
// identifier/sequence round-trip through Marshal + ParseICMPEchoReply.
func TestBuildICMPMessage(t *testing.T) {
	tests := []struct {
		name     string
		proto    Protocol
		wantType uint8
	}{
		{name: "ipv4 uses echo request", proto: Protocol(4), wantType: uint8(ipv4.ICMPTypeEcho)},
		{name: "ipv6 uses echo request", proto: Protocol(6), wantType: uint8(ipv6.ICMPTypeEchoRequest)},
	}

	const id = 0x1234
	const seq = Sequence(0x00ab)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := buildICMPMessage(id, seq, tt.proto)

			wb, err := msg.Marshal(nil)
			if err != nil {
				t.Fatalf("msg.Marshal(nil) err = %v", err)
			}

			reply, err := ParseICMPEchoReply(wb)
			if err != nil {
				t.Fatalf("ParseICMPEchoReply err = %v", err)
			}
			if reply.Type != tt.wantType {
				t.Errorf("Type = %d, want %d", reply.Type, tt.wantType)
			}
			if reply.Identifier != id {
				t.Errorf("Identifier = %#x, want %#x", reply.Identifier, id)
			}
			if reply.Seq != uint16(seq) {
				t.Errorf("Seq = %#x, want %#x", reply.Seq, uint16(seq))
			}
		})
	}
}

// TestLoopbackAddrClassification guards the assumption the engine relies on:
// netip.ParseAddr classifies the loopback inputs used throughout the tests, and
// Is4/Is6 drive the proto selection in PingerConfig.
func TestLoopbackAddrClassification(t *testing.T) {
	tests := []struct {
		addr    string
		wantIs4 bool
		wantIs6 bool
	}{
		{addr: "127.0.0.1", wantIs4: true, wantIs6: false},
		{addr: "127.0.0.2", wantIs4: true, wantIs6: false},
		{addr: "::1", wantIs4: false, wantIs6: true},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			ip, err := netip.ParseAddr(tt.addr)
			if err != nil {
				t.Fatalf("netip.ParseAddr(%q) err = %v", tt.addr, err)
			}
			if ip.Is4() != tt.wantIs4 {
				t.Errorf("%s: Is4() = %t, want %t", tt.addr, ip.Is4(), tt.wantIs4)
			}
			if ip.Is6() != tt.wantIs6 {
				t.Errorf("%s: Is6() = %t, want %t", tt.addr, ip.Is6(), tt.wantIs6)
			}
		})
	}
}
