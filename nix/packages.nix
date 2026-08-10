# No `apps.default`: the crate is a library and installs no binary.
{ ... }:
{
  perSystem =
    { pkgs, craneLib, ... }:
    let
      desec = pkgs.callPackage ./_package.nix { inherit craneLib; };

      # Clippy, the tests and the docs are three more consumers of the one dependency
      # build the package already paid for, so each only compiles this crate.
      #
      # They are also leaves: nothing builds on their target directory, and crane would
      # otherwise re-export a copy of it from each, putting three near-identical archives
      # into a store that CI has to carry between runs.
      checkArgs = desec.commonArgs // {
        inherit (desec) cargoArtifacts;
        doInstallCargoArtifacts = false;
      };
    in
    {
      packages.default = desec;

      checks = {
        inherit desec;

        clippy = craneLib.cargoClippy (
          checkArgs // { cargoClippyExtraArgs = "--all-targets -- -D warnings"; }
        );

        # The live tests talk to the real deSEC API and are #[ignore]d, so this runs the
        # mock suite only, exactly as `just test` did.
        tests = craneLib.cargoTest checkArgs;

        docs = craneLib.cargoDoc checkArgs;
      };
    };
}
