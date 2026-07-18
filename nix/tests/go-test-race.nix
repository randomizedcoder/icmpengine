# nix/tests/go-test-race.nix
#
# Race-detector run over the *pure-unit* subset (same scoping as go-unit.nix:
# socket integration tests can't run in the hermetic sandbox).
#
# The Go race detector requires cgo, so this derivation enables CGO_ENABLED=1
# and adds gcc (the rest of the repo's Nix builds default to CGO_ENABLED=0).
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
pkgs.runCommand "icmpengine-test-go-race"
  {
    nativeBuildInputs = [
      versions.go
      pkgs.gcc # race detector needs cgo
    ];
    inherit vendoredSource;
  }
  ''
    cp -r $vendoredSource ./icmpengine && chmod -R +w ./icmpengine
    cd ./icmpengine
    export HOME=$(mktemp -d)
    export CGO_ENABLED=1
    export GOFLAGS=-mod=vendor

    set +e
    go test -race -count=1 -timeout 5m -run '${pureTests}' ./... > $out 2>&1
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
      cat $out >&2
      exit "$rc"
    fi
  ''
