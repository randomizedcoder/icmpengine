#
# flake.nix — icmpengine
#
# Thin orchestrator. Every concern lives under ./nix/ and is wired up here.
# See ./nix/default.nix for the per-system aggregator.
#
# Quick references:
#   nix develop                     # dev shell
#   nix build .#icmpengine          # main binary (default variant)
#   nix build .#icmpengine-debug    # debug variant (keeps symbols/DWARF)
#   nix build .#icmpengine-stripped # smallest
#   nix build .#oci-icmpengine      # OCI image (load via `./result | docker load`)
#   nix flake check                 # gofmt + nix-fmt + go-vet + golangci-lint + smokes + race
#
{
  description = "icmpengine — non-privileged ICMP echo request/reply engine";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        "aarch64-linux"
      ]
      (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          lib = nixpkgs.lib;

          aggregator = import ./nix {
            inherit pkgs lib;
            src = ./.;
          };
        in
        {
          inherit (aggregator)
            packages
            devShells
            checks
            apps
            ;
        }
      )
    // {
      overlays.default = import ./nix/overlays.nix { inherit self; };
    };
}
