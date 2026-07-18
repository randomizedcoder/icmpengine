# nix/lib/mkOciImage.nix
#
# Wraps `pkgs.dockerTools.streamLayeredImage` with a standard layout for
# icmpengine OCI images.
#
# Conventions:
#   - Binaries land under /bin/
#   - Entrypoint defaults to /bin/icmpengine
#
# Note: icmpengine opens non-privileged ICMP ("ping") sockets at runtime, which
# need either NET_RAW or a permissive net.ipv4.ping_group_range. The image build
# itself is unprivileged.
#
{ pkgs, lib }:

{
  name,
  tag ? "latest",
  binaries, # derivation containing /bin/*
  exposedPorts ? [ ],
  entrypoint ? "/bin/icmpengine",
}:

let
  exposedPortsAttr = lib.listToAttrs (
    map (p: {
      name = "${toString p}/tcp";
      value = { };
    }) exposedPorts
  );
in
pkgs.dockerTools.streamLayeredImage {
  inherit name tag;
  contents = [ binaries ];

  config = {
    Entrypoint = [ entrypoint ];
    ExposedPorts = exposedPortsAttr;
  };
}
