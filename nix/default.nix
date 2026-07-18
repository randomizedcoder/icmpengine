# nix/default.nix
#
# Aggregator. Returns the per-system attribute set consumed by flake.nix.
#
{
  pkgs,
  lib,
  src,
}:

let
  versions = import ./versions.nix { inherit pkgs; };

  # Per-binary derivations (icmpengine × {debug,default,stripped}).
  binaries = import ./binaries.nix { inherit pkgs lib src; };

  # Vendored source (used by every check/test that needs Go deps in the sandbox).
  goMods = import ./lib/goModules.nix {
    inherit pkgs lib src;
    vendorHash = versions.goVendorHash;
  };
  vendoredSource = goMods.vendoredSource;

  # OCI image(s) — one per build variant.
  containers = import ./containers { inherit pkgs lib binaries; };

  # Static analysis checks.
  checks = import ./checks {
    inherit
      pkgs
      lib
      src
      vendoredSource
      binaries
      ;
  };

  # Behavioural test runners.
  tests = import ./tests { inherit pkgs lib vendoredSource; };

  # Tier 2 lint — exposed as a package (non-gating), not a check.
  golangci-lint-comprehensive = import ./checks/golangci-lint-comprehensive.nix {
    inherit pkgs lib vendoredSource;
  };

  # Pedantic code-quality aggregator (every tool, never fails, one markdown report).
  qualityReport = import ./quality-report { inherit pkgs lib vendoredSource; };

  # Dev shell.
  devshell = import ./devshell.nix { inherit pkgs lib; };
in
{
  packages =
    # Per-binary attrs (icmpengine, icmpengine-debug, icmpengine-stripped, default).
    (removeAttrs binaries [ "byVariant" ]) // {
      # OCI images.
      inherit (containers)
        oci-icmpengine
        oci-icmpengine-debug
        oci-icmpengine-stripped
        ;

      # Test runners exposed as buildable packages.
      test-go-unit = tests.go-unit;
      test-go-race = tests.go-race;

      # Tier 2 lint + aggregated quality report (buildable, non-gating).
      inherit golangci-lint-comprehensive;
      quality-report = qualityReport;
    };

  devShells.default = devshell;

  checks = checks // {
    # Race-detector run participates in `nix flake check`.
    test-go-race = tests.go-race;
  };

  apps = {
    default = {
      type = "app";
      program = "${binaries.icmpengine}/bin/icmpengine";
      meta.description = "Run the icmpengine CLI (non-privileged ICMP ping engine)";
    };
    quality-report = {
      type = "app";
      program = "${qualityReport}/bin/quality-report";
      meta.description = "Print the aggregated static-analysis quality report";
    };
  };
}
