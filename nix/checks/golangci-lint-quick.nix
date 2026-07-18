# nix/checks/golangci-lint-quick.nix
#
# Tier 0: gofmt, goimports, govet, errcheck, ineffassign, unused, staticcheck.
# Target wall time: ~30 seconds.
#
{
  pkgs,
  lib,
  vendoredSource,
}:

let
  versions = import ../versions.nix { inherit pkgs; };
in
pkgs.runCommand "icmpengine-golangci-lint-quick"
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
    export GOPATH=$HOME/go
    export GOMODCACHE=$HOME/go/pkg/mod
    export GOCACHE=$HOME/go-build
    export GOPROXY=off
    export CGO_ENABLED=0
    export GOFLAGS=-mod=vendor
    golangci-lint run --config .golangci-quick.yml --timeout 5m ./... > $out 2>&1 \
      || (cat $out && exit 1)
  ''
