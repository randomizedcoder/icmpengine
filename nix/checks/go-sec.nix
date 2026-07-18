# nix/checks/go-sec.nix
#
# Security scan via gosec.
#
# Exclusions (each justified in-place):
#   G404 — math/rand: FakeDrop simulates ping loss with non-crypto randomness;
#          a CSPRNG would be pointless there (the only math/rand use).
#   G115 — int -> uint16 conversion of the CLI --count into an ICMP sequence
#          number. cmd/icmpengine bounds --count to 0..65535 at startup, so the
#          conversion cannot overflow; gosec's flow analysis can't see the guard.
#
# NOT excluded — these would block the build if found:
#   G104 (unhandled errors), G114 (HTTP serve without timeouts),
#   G401/G501 (weak crypto), etc.
#
{
  pkgs,
  lib,
  vendoredSource,
}:

let
  versions = import ../versions.nix { inherit pkgs; };
in
pkgs.runCommand "icmpengine-gosec"
  {
    nativeBuildInputs = [
      versions.go
      versions.gosec
    ];
    inherit vendoredSource;
  }
  ''
    cp -r $vendoredSource ./icmpengine && chmod -R +w ./icmpengine
    cd ./icmpengine
    export HOME=$(mktemp -d)
    export CGO_ENABLED=0
    export GOFLAGS=-mod=vendor
    gosec -exclude=G404,G115 -fmt=text ./... > $out 2>&1 || {
      rc=$?
      cat $out
      exit "$rc"
    }
  ''
