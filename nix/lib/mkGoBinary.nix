# nix/lib/mkGoBinary.nix
#
# Builds a single Go binary from ./cmd/<name>/.
#
# Parameters:
#   name           — binary name (matches cmd/<name>/)
#   src            — source tree (typically the repo root)
#   subPath        — subdir with the main package (default cmd/${name})
#   variant        — one of "debug", "default", "stripped" (see versions.nix
#                    buildVariants). Drives ldflags, the strip(1) pass, and
#                    the derivation pname suffix.
#   tag, commit,
#   date           — injected into main.{tag,commit,date} via -ldflags -X.
#                    (cmd/icmpengine/main.go declares vars tag/commit/date —
#                     note: main.tag, NOT main.version.)
#   extraLdflags   — additional -ldflags entries appended after the variant's
#   doCheck        — run `go test ./...` during build (default false; tests run
#                    as separate Nix checks instead)
#
{
  pkgs,
  lib,
}:

let
  versions = import ../versions.nix { inherit pkgs; };
  buildGoModule = pkgs.buildGoModule;
in
{
  name,
  src,
  subPath ? "cmd/${name}",
  variant ? "default",
  vendorHash ? versions.goVendorHash,
  tag ? "0.0.0-nix",
  commit ? "nix",
  date ? "1970-01-01-00:00",
  extraLdflags ? [ ],
  doCheck ? false,
}:

let
  variantCfg =
    versions.buildVariants.${variant}
      or (throw "mkGoBinary: unknown variant '${variant}'; expected one of ${toString (builtins.attrNames versions.buildVariants)}");
in
buildGoModule {
  pname = "${name}${variantCfg.tagSuffix}";
  version = tag;
  inherit
    src
    vendorHash
    doCheck
    ;

  subPackages = [ subPath ];

  env = {
    CGO_ENABLED = if versions.cgoEnabled then "1" else "0";
  };

  tags = versions.buildTags;

  ldflags =
    variantCfg.extraLdflags
    ++ [
      "-X main.tag=${tag}"
      "-X main.commit=${commit}"
      "-X main.date=${date}"
    ]
    ++ extraLdflags;

  preBuild = ''
    export GOFLAGS="-trimpath ''${GOFLAGS:-}"
  '';

  # Filippo's trick: `strip` after -s -w shaves a bit more off. Only applied
  # to the "stripped" variant. Other variants explicitly disable Nix's
  # automatic strip so the debug variant keeps its symbols.
  dontStrip = !variantCfg.doStrip;
  postFixup = lib.optionalString variantCfg.doStrip ''
    for bin in $out/bin/*; do
      ${pkgs.binutils-unwrapped}/bin/strip --strip-all "$bin"
    done
  '';

  meta = with lib; {
    description = "icmpengine ${name} (${variant}) — non-privileged ICMP ping engine";
    homepage = "https://github.com/randomizedcoder/icmpengine";
    # No LICENSE file in the repo yet; update once one is added.
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = name;
  };
}
