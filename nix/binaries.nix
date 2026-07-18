# nix/binaries.nix
#
# Enumerates the buildable `cmd/<name>/` entries and produces a derivation for
# each {binary} × {variant} cell. icmpengine has a single binary, so this is
# just the `icmpengine` cmd across the debug/default/stripped variants.
#
# Top-level exports (visible in `nix flake show`):
#   icmpengine            default variant
#   icmpengine-debug      debug variant (symbols + DWARF)
#   icmpengine-stripped   stripped variant (smallest)
#   default               = icmpengine
#   byVariant             internal nested attrset consumed by containers/
#
{
  pkgs,
  lib,
  src,
  tag ? "0.0.0-nix",
  commit ? "nix",
  date ? "1970-01-01-00:00",
}:

let
  versions = import ./versions.nix { inherit pkgs; };
  mkGoBinary = import ./lib/mkGoBinary.nix { inherit pkgs lib; };

  binaryNames = [ "icmpengine" ];
  variantNames = builtins.attrNames versions.buildVariants;

  # byVariant.<variant>.<cmd>: every cmd in every build variant.
  byVariant = lib.genAttrs variantNames (
    variant:
    lib.genAttrs binaryNames (
      name:
      mkGoBinary {
        inherit
          name
          src
          variant
          tag
          commit
          date
          ;
      }
    )
  );

  defaultBinaries = byVariant.default;
in
defaultBinaries
// {
  default = defaultBinaries.icmpengine;

  icmpengine-debug = byVariant.debug.icmpengine;
  icmpengine-stripped = byVariant.stripped.icmpengine;

  # Internal nested set for downstream consumers (containers/).
  inherit byVariant;
}
