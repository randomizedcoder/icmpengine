# nix/checks/cli-version-smoke.nix
#
# Runs the built binary's `--version` and checks the ldflags-injected fields
# show up. Hermetic: `--version` prints main.{tag,commit,date} and exits 0
# without opening any sockets.
#
{
  pkgs,
  lib,
  binaries,
}:

pkgs.runCommand "icmpengine-cli-version-smoke" { } ''
  out_text=$(${binaries.icmpengine}/bin/icmpengine --version 2>&1)
  echo "$out_text"
  # mkGoBinary injects tag=0.0.0-nix / commit=nix / date=1970-01-01-00:00.
  echo "$out_text" | grep -q "commit: nix" || {
    echo "cli-version-smoke: expected injected commit not found in --version output" >&2
    exit 1
  }
  echo "cli-version-smoke: ok" > $out
''
