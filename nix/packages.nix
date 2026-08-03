# No `apps.default`: the crate is a library and installs no binary.
{ ... }:
{
  perSystem =
    { pkgs, ... }:
    rec {
      checks.desec = packages.default;

      packages.default = pkgs.callPackage ./_package.nix { };
    };
}
