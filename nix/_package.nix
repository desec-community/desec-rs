# The build definition, shared by this flake's packages and by the overlay.
#
# Taking `pkgs` as an argument (rather than closing over this flake's own) is what
# lets the overlay build against the consumer's nixpkgs, so downstream can override
# and cross-compile it.
{
  lib,
  rustPlatform,
  cacert,
  ...
}:
rustPlatform.buildRustPackage {
  pname = "desec";
  version = "0.0.1";

  # reqwest's rustls backend loads the system trust store when a client is constructed,
  # not when a request is made, so every test that builds a Client fails in the sandbox
  # with "No CA certificates were loaded from the system". The mock tests only ever talk
  # to loopback over plain HTTP; this is purely to get past client construction.
  SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";

  # Naming the inputs explicitly keeps target/ and .direnv/ out of the store, and
  # means an unrelated edit does not invalidate the build.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../crates
      ../README.md
    ];
  };
  cargoLock.lockFile = ../Cargo.lock;

  cargoBuildFlags = [
    "--package"
    "desec"
  ];

  meta = {
    description = "deSEC.io DNS API client library";
    license = with lib.licenses; [
      mit
      asl20
    ];
  };
}
