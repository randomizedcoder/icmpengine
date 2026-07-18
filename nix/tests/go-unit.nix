# nix/tests/go-unit.nix
#
# Runs the *pure-unit* subset of the Go test suite.
#
# SCOPE: the hermetic Nix build sandbox cannot open non-privileged ICMP
# sockets (restricted net.ipv4.ping_group_range, no privileges), so the
# loopback integration tests (TestPinger*, TestPingerWithStatsChannel,
# TestRunStopLoop, TestPingerFakeDrop, TestPingerFakeSuccess) are NOT run
# here — they would fail at icmp.ListenPacket. Those run in GitHub Actions
# CI, which sets the sysctl. This check covers the socket-free unit tests
# only. `go build ./...` (via the package build) + `go vet ./...` cover
# that the socket code still compiles.
#
{
  pkgs,
  lib,
  vendoredSource,
}:

let
  versions = import ../versions.nix { inherit pkgs; };
  pureTests = "^(TestParseICMPEchoReply|TestFakeDrop|TestBuildICMPMessage|TestLoopbackAddrClassification|TestTiarCalculator)$";
in
pkgs.runCommand "icmpengine-go-unit"
  {
    nativeBuildInputs = [ versions.go ];
    inherit vendoredSource;
  }
  ''
    cp -r $vendoredSource ./icmpengine && chmod -R +w ./icmpengine
    cd ./icmpengine
    export HOME=$(mktemp -d)
    export CGO_ENABLED=0
    export GOFLAGS=-mod=vendor
    echo "NOTE: running socket-free unit subset only (see nix/tests/go-unit.nix)."
    go test -run '${pureTests}' -v ./... > $out 2>&1 || (cat $out && exit 1)
  ''
