# nix/versions.nix
#
# Pinned tool versions for the icmpengine Nix flake.
#
# Single source of truth — every other module reads from here.
# Changing a version here propagates to dev shell, build derivations, and checks.
#
{ pkgs }:

{
  # Go toolchain. Must satisfy go.mod's `go 1.26.4` directive.
  # nixpkgs unstable ships go_1_26; fall back to `go` (latest) if not.
  # NOTE: nixos-unstable currently packages Go 1.26.4. go.mod's floor is
  # 1.26.4 to match; bump both together once unstable moves to 1.26.5+.
  go = pkgs.go_1_26 or pkgs.go;

  # Static analysis
  golangci-lint = pkgs.golangci-lint;
  gosec = pkgs.gosec;
  nixfmt = pkgs.nixfmt;

  # Per-variant build configuration. mkGoBinary picks one by name.
  #
  # Reference: https://words.filippo.io/shrink-your-go-binaries-with-this-one-weird-trick/
  #
  #   debug    — plain `go build` output. Keeps the symbol table and DWARF
  #              debug info. Largest; works directly with delve.
  #   default  — `-ldflags "-s -w"`. Drops the symbol table (-s) and DWARF
  #              info (-w). ~25% smaller. Production default.
  #   stripped — default + binutils `strip`. Smallest.
  buildVariants = {
    debug = {
      extraLdflags = [ ];
      doStrip = false;
      tagSuffix = "-debug";
    };
    default = {
      extraLdflags = [
        "-s"
        "-w"
      ];
      doStrip = false;
      tagSuffix = "";
    };
    stripped = {
      extraLdflags = [
        "-s"
        "-w"
      ];
      doStrip = true;
      tagSuffix = "-stripped";
    };
  };

  # Static linking, no libc — icmpengine is pure Go.
  buildTags = [
    "netgo"
    "osusergo"
  ];
  cgoEnabled = false;

  # Go vendor hash. Update by running `nix build .#icmpengine` and pasting the
  # `got:` value from the hash mismatch error. Used by every Nix check that
  # needs deps in the sandbox (see nix/lib/goModules.nix).
  goVendorHash = "sha256-AxO1zRTaPOBAHI4kEzsZZnO54c7XsVbbqfScLhumutg=";
}
