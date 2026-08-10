# The build definition, shared by this flake's packages, the checks and the overlay.
#
# Taking `pkgs` as an argument (rather than closing over this flake's own) is what
# lets the overlay build against the consumer's nixpkgs, so downstream can override
# and cross-compile it. craneLib comes in the same way, for the same reason.
#
# Dependencies compile in their own derivation, whose inputs are Cargo.lock and the
# toolchain rather than the crate's sources. A commit that touches only src/ therefore
# reuses it instead of compiling the tree again. `passthru` re-exports the pieces so the
# checks build against that same derivation rather than each paying for their own.
{
  lib,
  craneLib,
  cacert,
  ...
}:
let
  commonArgs = {
    pname = "desec";
    version = "0.0.2";

    # Naming the inputs explicitly keeps target/ and .direnv/ out of the store, and
    # means an unrelated edit does not invalidate the build. README.md is here because
    # lib.rs includes it as the crate-level doc.
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../Cargo.toml
        ../Cargo.lock
        ../crates
        ../README.md
      ];
    };

    # --all-features is what the justfile has always linted, tested and documented with,
    # and it costs nothing here: probes declares no dependencies, so enabling it leaves
    # the dependency graph identical to the default feature set. What it does buy is that
    # probes.rs and the probe-gated blocks in tests/live.rs still get compiled, which no
    # other check does -- the live workflow is workflow_dispatch only.
    cargoExtraArgs = "--locked --all-features";

    strictDeps = true;

    # reqwest's rustls backend loads the system trust store when a client is constructed,
    # not when a request is made, so every test that builds a Client fails in the sandbox
    # with "No CA certificates were loaded from the system". The mock tests only ever talk
    # to loopback over plain HTTP; this is purely to get past client construction.
    SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;

    # checks.tests runs the suite as its own derivation, so a red run names the failure
    # rather than reporting that the package did not build.
    doCheck = false;

    meta = {
      description = "deSEC.io DNS API client library";
      license = with lib.licenses; [
        mit
        asl20
      ];
    };

    passthru = { inherit commonArgs cargoArtifacts; };
  }
)
