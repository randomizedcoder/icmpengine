# nix/checks/golangci-lint.nix
#
# golangci-lint over the vendored source tree, using .golangci.yml.
#
{
  pkgs,
  lib,
  vendoredSource,
}:

let
  versions = import ../versions.nix { inherit pkgs; };
in
pkgs.runCommand "icmpengine-golangci-lint"
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
    golangci-lint run --config .golangci.yml --timeout 5m ./... > $out 2>&1 \
      || (cat $out && exit 1)
  ''
