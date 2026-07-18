# nix/lib/goModules.nix
#
# Produces a derivation containing the icmpengine Go module dependencies as a
# vendor/ tree. Reused by every Nix check that needs Go deps in the sandbox.
#
# The `vendorHash` MUST be updated after the first build. On a fresh checkout:
#   nix build .#icmpengine 2>&1 | grep 'got:.*sha256-' | head -1
# then paste the value into versions.nix's `goVendorHash` slot.
#
{
  pkgs,
  lib,
  src,
  vendorHash,
}:

let
  # buildGoModule exposes `goModules` — a derivation containing the populated
  # vendor/ tree. No `subPackages` restriction: we want the FULL module graph
  # so lint/vet checks can type-check every package in the repo.
  parent = pkgs.buildGoModule {
    pname = "icmpengine";
    version = "vendored";
    inherit src vendorHash;
    env.CGO_ENABLED = "0";
    doCheck = false;
  };
in
{
  inherit (parent) goModules;
  # Convenience: a writable source tree with vendor/ already populated.
  vendoredSource = pkgs.runCommand "icmpengine-vendored-source" { } ''
    cp -r ${src}/. $out
    chmod -R +w $out
    cp -r ${parent.goModules} $out/vendor
  '';
}
