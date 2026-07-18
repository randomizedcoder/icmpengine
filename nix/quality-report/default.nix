# nix/quality-report/default.nix
#
# Code-quality aggregator: runs every static-analysis tool wired into the repo,
# never short-circuits on findings, and emits a single markdown report.
#
# Two consumers:
#   - packages.quality-report — the hermetic derivation. Produces
#     result/quality-report.md plus result/raw/* (per-tool captures).
#   - apps.quality-report — `nix run .#quality-report` cats the markdown.
#
# Self-contained: unlike xtcp2's version this renders the markdown in bash and
# has no Go aggregator tool / coverage-baseline machinery.
#
{
  pkgs,
  lib,
  vendoredSource,
}:

let
  versions = import ../versions.nix { inherit pkgs; };
in
pkgs.runCommand "icmpengine-quality-report"
  {
    nativeBuildInputs = [
      versions.go
      versions.golangci-lint
      versions.gosec
      versions.nixfmt
      pkgs.coreutils
      pkgs.findutils
      pkgs.gnugrep
    ];
    inherit vendoredSource;
    # Reports are the signal, not the exit code; keep the timestamp pinned so
    # two runs over the same source produce identical output.
    SOURCE_DATE_EPOCH = "1700000000";
  }
  ''
    set +e
    set -u
    cp -r $vendoredSource ./icmpengine && chmod -R +w ./icmpengine
    cd ./icmpengine

    export HOME=$(mktemp -d)
    export GOPATH=$HOME/go
    export GOMODCACHE=$HOME/go/pkg/mod
    export GOCACHE=$HOME/go-build
    export GOPROXY=off
    export CGO_ENABLED=0
    export GOFLAGS=-mod=vendor

    RAW=$(mktemp -d)
    : > "$RAW/exit-codes.txt"

    # runtool <label> <outpath> -- <cmd...>: capture stdout+stderr, record the
    # exit code, never propagate a non-zero exit to the surrounding script.
    runtool() {
      local label="$1" outpath="$2"; shift 2
      [ "$1" = "--" ] && shift
      "$@" > "$outpath" 2>&1
      echo "$label=$?" >> "$RAW/exit-codes.txt"
      return 0
    }

    runtool gofmt      "$RAW/gofmt.out"        -- sh -c 'gofmt -l . | grep -v -E "^vendor/" || true'
    runtool go-vet     "$RAW/go-vet.out"       -- go vet ./...
    runtool golangci-quick         "$RAW/golangci-quick.out"         -- golangci-lint run --config .golangci-quick.yml         --timeout 60s --max-issues-per-linter=0 --max-same-issues=0 ./...
    runtool golangci-standard      "$RAW/golangci-standard.out"      -- golangci-lint run --config .golangci.yml               --timeout 5m  --max-issues-per-linter=0 --max-same-issues=0 ./...
    runtool golangci-comprehensive "$RAW/golangci-comprehensive.out" -- golangci-lint run --config .golangci-comprehensive.yml --timeout 15m --max-issues-per-linter=0 --max-same-issues=0 ./...
    runtool gosec      "$RAW/gosec.out"        -- gosec -exclude=G404,G115 -fmt=text ./...
    runtool nix-fmt    "$RAW/nix-fmt.out"      -- sh -c 'find . -name "*.nix" -not -path "./vendor/*" -exec nixfmt --check {} + 2>&1 || true'
    # Socket-free unit subset (matches nix/tests/go-unit.nix).
    runtool go-test    "$RAW/go-test.out"      -- go test -run '^(TestParseICMPEchoReply|TestFakeDrop|TestBuildICMPMessage|TestLoopbackAddrClassification|TestTiarCalculator)$' ./...

    # ── Render markdown ────────────────────────────────────────────────
    mkdir -p $out $out/raw
    cp -r "$RAW"/. $out/raw/ || true

    status() { # exit code -> emoji + word
      if [ "$1" = "0" ]; then echo "✅ pass"; else echo "⚠️ findings"; fi
    }
    getrc() { grep -m1 "^$1=" "$RAW/exit-codes.txt" | cut -d= -f2; }

    {
      echo "# icmpengine — code quality report"
      echo
      echo "Tool versions: go \`$(go version | awk '{print $3}')\`,"
      echo "golangci-lint \`$(golangci-lint version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)\`,"
      echo "gosec \`$(gosec -version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)\`."
      echo
      echo "| Tool | Result |"
      echo "| --- | --- |"
      for t in gofmt go-vet golangci-quick golangci-standard golangci-comprehensive gosec nix-fmt go-test; do
        echo "| $t | $(status "$(getrc "$t")") |"
      done
      echo
      echo "> The three golangci tiers are quick (Tier 0), standard (Tier 1, CI-gating),"
      echo "> and comprehensive (Tier 2, non-gating). Full per-tool output is under \`raw/\`."
      echo
      for t in golangci-standard golangci-comprehensive gosec; do
        rc=$(getrc "$t")
        if [ "$rc" != "0" ]; then
          echo "## $t findings"
          echo
          echo '```'
          tail -n 60 "$RAW/$t.out"
          echo '```'
          echo
        fi
      done
    } > $out/quality-report.md

    mkdir -p $out/bin
    cat > $out/bin/quality-report <<EOF
    #!${pkgs.runtimeShell}
    exec ${pkgs.coreutils}/bin/cat $out/quality-report.md
    EOF
    chmod +x $out/bin/quality-report
  ''
