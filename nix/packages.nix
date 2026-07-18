# nix/packages.nix
#
# Package sets for icmpengine.
#
#   - nativeBuildInputs: build-time tools
#   - buildInputs: link/runtime libs (pure Go → empty)
#   - devTools: extras for the developer shell only
#
{ pkgs }:

let
  versions = import ./versions.nix { inherit pkgs; };
in
rec {
  # Build-time only (used inside derivations).
  nativeBuildInputs = [
    versions.go
    pkgs.git
    pkgs.cacert
  ];

  # Link/runtime deps. icmpengine is pure Go (CGO_ENABLED=0) so this stays empty.
  buildInputs = [ ];

  # Developer shell only.
  devTools = with pkgs; [
    # Go ecosystem
    versions.go
    gopls
    gotools
    delve
    go-tools # staticcheck etc.
    versions.golangci-lint
    versions.gosec

    # Network debugging
    iproute2
    tcpdump

    # HTTP / plumbing
    curl
    jq

    # Container inspection (dockerTools images without docker)
    skopeo

    # Nix tooling
    versions.nixfmt
  ];

  # Combined list (everything for the dev shell).
  allDevPackages = nativeBuildInputs ++ buildInputs ++ devTools;
}
