# nix/overlays.nix
#
# Overlay so downstream consumers can `inputs.icmpengine.overlays.default` and
# pick up the icmpengine binary + OCI image from their own pkgs set.
#
# Usage in a consumer flake:
#   inputs.icmpengine.url = "github:randomizedcoder/icmpengine";
#   outputs = { nixpkgs, icmpengine, ... }: let
#     pkgs = import nixpkgs {
#       overlays = [ icmpengine.overlays.default ];
#       system = "x86_64-linux";
#     };
#   in { packages.default = pkgs.icmpengine; };
#
{ self }:

final: prev: {
  icmpengine = self.packages.${final.system}.icmpengine or null;
  icmpengine-oci = self.packages.${final.system}.oci-icmpengine or null;
}
