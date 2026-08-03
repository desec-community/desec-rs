{ ... }:
{
  flake.overlays.default = final: _prev: {
    desec = final.callPackage ./_package.nix { };
  };
}
