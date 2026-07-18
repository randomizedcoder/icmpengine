# nix/checks/go-vet.nix
#
# `go vet ./...` against the vendored source tree.
#
{
  pkgs,
  lib,
  vendoredSource,
}:

let
  versions = import ../versions.nix { inherit pkgs; };
in
pkgs.runCommand "icmpengine-go-vet"
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
    go vet ./... > $out 2>&1 || (cat $out && exit 1)
  ''
