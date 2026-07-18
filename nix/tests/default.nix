# nix/tests/default.nix
#
# Behavioural test runners.
#
{
  pkgs,
  lib,
  vendoredSource,
}:

{
  go-unit = import ./go-unit.nix { inherit pkgs lib vendoredSource; };
  go-race = import ./go-test-race.nix { inherit pkgs lib vendoredSource; };
}
