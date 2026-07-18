# nix/checks/default.nix
#
# Aggregates the `nix flake check` static-analysis + smoke targets.
#
{
  pkgs,
  lib,
  src,
  vendoredSource,
  binaries,
}:

{
  gofmt = import ./gofmt.nix { inherit pkgs lib src; };
  nix-fmt = import ./nix-fmt.nix { inherit pkgs lib src; };
  go-vet = import ./go-vet.nix { inherit pkgs lib vendoredSource; };
  # golangci-lint Tier 0 (quick) + Tier 1 (standard) both gate CI.
  golangci-lint-quick = import ./golangci-lint-quick.nix { inherit pkgs lib vendoredSource; };
  golangci-lint = import ./golangci-lint.nix { inherit pkgs lib vendoredSource; };
  go-sec = import ./go-sec.nix { inherit pkgs lib vendoredSource; };
  cli-version-smoke = import ./cli-version-smoke.nix { inherit pkgs lib binaries; };
  # Tier 2 (comprehensive) is intentionally NOT here — it is exposed as a
  # buildable package instead (see nix/default.nix) so its noisier findings
  # don't gate `nix flake check`.
}
