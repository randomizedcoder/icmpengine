# nix/checks/golangci-lint-comprehensive.nix
#
# Tier 2: Comprehensive lint. Tier 1 + exhaustive, prealloc, gocyclo, funlen,
# goconst, dupl, unconvert, nakedret, misspell. Target wall time: ~10 minutes.
#
# NOT part of the default `nix flake check` — it is exposed as a buildable
# package (nix build .#golangci-lint-comprehensive) so its (often noisy)
# findings don't gate CI.
#
{
  pkgs,
  lib,
  vendoredSource,
}:

let
  versions = import ../versions.nix { inherit pkgs; };
in
pkgs.runCommand "icmpengine-golangci-lint-comprehensive"
  {
    nativeBuildInputs = [
      versions.go
      versions.golangci-lint
    ];
    inherit vendoredSource;
  }
  ''
    cp -r $vendoredSource ./icmpengine && chmod -R +w ./icmpengine
    cd ./icmpengine
    export HOME=$(mktemp -d)
    export CGO_ENABLED=0
    export GOFLAGS=-mod=vendor
    golangci-lint run --config .golangci-comprehensive.yml --timeout 15m ./... > $out 2>&1 \
      || (cat $out && exit 1)
  ''
