package icmpengine

import (
	"bytes"
	"errors"
	"testing"
)

// makeEchoReplyBytes builds a wire-format ICMP echo reply for tests.
// Layout (big-endian): Type(1) Code(1) Checksum(2) Identifier(2) Seq(2) [data...]
func makeEchoReplyBytes(typ, code uint8, checksum, id, seq uint16, dataLen int) []byte {
	b := []byte{
		typ,
		code,
		byte(checksum >> 8), byte(checksum),
		byte(id >> 8), byte(id),
		byte(seq >> 8), byte(seq),
	}
	if dataLen > 0 {
		b = append(b, make([]byte, dataLen)...)
	}
	return b
}

func TestParseICMPEchoReply(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    ICMPEchoReply
		wantErr error
	}{
		{
			name:  "ipv4 echo reply",
			input: makeEchoReplyBytes(0, 0, 0xf7ff, 0xabcd, 0x0007, 0),
			want:  ICMPEchoReply{Type: 0, Code: 0, Checksum: 0xf7ff, Identifier: 0xabcd, Seq: 0x0007},
		},
		{
			name:  "ipv6 echo reply",
			input: makeEchoReplyBytes(129, 0, 0x1234, 0x00ff, 0x00ff, 0),
			want:  ICMPEchoReply{Type: 129, Code: 0, Checksum: 0x1234, Identifier: 0x00ff, Seq: 0x00ff},
		},
		{
			name:  "with data payload is ignored",
			input: makeEchoReplyBytes(0, 0, 0x0000, 0x1111, 0x2222, 56),
			want:  ICMPEchoReply{Type: 0, Code: 0, Checksum: 0x0000, Identifier: 0x1111, Seq: 0x2222},
		},
		{
			name:  "exactly 8 bytes boundary",
			input: makeEchoReplyBytes(8, 0, 0xffff, 0xffff, 0xffff, 0),
			want:  ICMPEchoReply{Type: 8, Code: 0, Checksum: 0xffff, Identifier: 0xffff, Seq: 0xffff},
		},
		{
			name:    "too short (7 bytes)",
			input:   []byte{0, 0, 0, 0, 0, 0, 0},
			wantErr: errMessageTooShort,
		},
		{
			name:    "empty",
			input:   []byte{},
			wantErr: errMessageTooShort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// []byte variant
			got, err := ParseICMPEchoReply(tt.input)
			assertEchoReply(t, "ParseICMPEchoReply", got, err, tt.want, tt.wantErr)

			// bytes.Buffer variant must behave identically
			var buf bytes.Buffer
			buf.Write(tt.input)
			gotBB, errBB := ParseICMPEchoReplyBB(buf)
			assertEchoReply(t, "ParseICMPEchoReplyBB", gotBB, errBB, tt.want, tt.wantErr)
		})
	}
}

func assertEchoReply(t *testing.T, fn string, got *ICMPEchoReply, err error, want ICMPEchoReply, wantErr error) {
	t.Helper()
	if wantErr != nil {
		if !errors.Is(err, wantErr) {
			t.Errorf("%s: err = %v, want %v", fn, err, wantErr)
		}
		if got != nil {
			t.Errorf("%s: got = %+v, want nil on error", fn, got)
		}
		return
	}
	if err != nil {
		t.Fatalf("%s: unexpected err = %v", fn, err)
	}
	if *got != want {
		t.Errorf("%s: got = %+v, want %+v", fn, *got, want)
	}
}

var benchInput = makeEchoReplyBytes(0, 0, 0xf7ff, 0xabcd, 0x0007, 56)

func BenchmarkParseICMPEchoReply(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseICMPEchoReply(benchInput); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseICMPEchoReplyBB(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		var buf bytes.Buffer
		buf.Write(benchInput)
		if _, err := ParseICMPEchoReplyBB(buf); err != nil {
			b.Fatal(err)
		}
	}
}
