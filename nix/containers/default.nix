# nix/containers/default.nix
#
# OCI images — one per build variant, each carrying the single icmpengine
# binary built with that variant.
#
#   oci-icmpengine           variant=default  (-s -w)
#   oci-icmpengine-debug     variant=debug    (full symbols/DWARF)
#   oci-icmpengine-stripped  variant=stripped (smallest)
#
# Load:
#   nix build .#oci-icmpengine && ./result | docker load
#   docker run --rm icmpengine:latest --version
#
# Runtime ping needs NET_RAW or a permissive ping_group_range sysctl:
#   docker run --rm --sysctl net.ipv4.ping_group_range="0 2147483647" \
#     icmpengine:latest --dest 127.0.0.1 --count 3
#
{
  pkgs,
  lib,
  binaries,
}:

let
  mkOciImage = import ../lib/mkOciImage.nix { inherit pkgs lib; };

  mkImage =
    {
      variant,
      tag,
    }:
    mkOciImage {
      name = "icmpengine";
      inherit tag;
      binaries = binaries.byVariant.${variant}.icmpengine;
      exposedPorts = [ 8889 ]; # prometheus /metrics default (-promBind)
      entrypoint = "/bin/icmpengine";
    };
in
{
  oci-icmpengine = mkImage {
    variant = "default";
    tag = "latest";
  };
  oci-icmpengine-debug = mkImage {
    variant = "debug";
    tag = "debug";
  };
  oci-icmpengine-stripped = mkImage {
    variant = "stripped";
    tag = "stripped";
  };
}
