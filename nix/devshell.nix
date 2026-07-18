# nix/devshell.nix
#
# Developer environment. `nix develop` lands here.
#
{ pkgs, lib }:

let
  versions = import ./versions.nix { inherit pkgs; };
  packages = import ./packages.nix { inherit pkgs; };
in
pkgs.mkShell {
  name = "icmpengine-dev";

  packages = packages.allDevPackages;

  shellHook = ''
        export CGO_ENABLED=0

        icmpengine-help() {
          cat <<'EOF'

    icmpengine dev shell
    ====================
    Build:
      nix build .#icmpengine              Build the main binary (default variant)
      nix build .#icmpengine-debug        Debug variant (symbols + DWARF)
      nix build .#icmpengine-stripped     Smallest
      nix build .#oci-icmpengine          Build the OCI image

    Test / lint:
      go test ./...                       Full suite (loopback ICMP; see note below)
      lint-quick                          Tier 0  (~30s, pre-commit)
      lint                                Tier 1  (~2min, CI gating)
      lint-comprehensive                  Tier 2  (~10min, on-demand)
      lint-fix                            Apply auto-fixable findings
      gosec                               Security scan
      nix build .#quality-report          Aggregate every tool into one report
      nix flake check                     Tier 0+1 + gosec + gofmt + nix-fmt + go-vet + smokes + race

    Run:
      ./result/bin/icmpengine --dest 127.0.0.1,::1 --count 5

    Note: opening non-privileged ICMP sockets needs a permissive sysctl:
      sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"

    EOF
        }

        lint-quick() {
          ${versions.golangci-lint}/bin/golangci-lint run \
            --config .golangci-quick.yml --timeout 5m ./...
        }

        lint() {
          ${versions.golangci-lint}/bin/golangci-lint run \
            --config .golangci.yml --timeout 5m ./...
        }

        lint-comprehensive() {
          ${versions.golangci-lint}/bin/golangci-lint run \
            --config .golangci-comprehensive.yml --timeout 15m ./...
        }

        lint-fix() {
          ${versions.golangci-lint}/bin/golangci-lint run \
            --config .golangci.yml --fix ./...
        }

        icmpengine-help
  '';
}
