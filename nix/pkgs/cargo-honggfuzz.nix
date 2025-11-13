{
  lib,
  stdenv,
  fetchCrate,
  rustPlatform,
}:
rustPlatform.buildRustPackage rec {
  pname = "honggfuzz";
  # last tagged version is far behind master
  version = "0.5.55";

  src = fetchCrate {
    inherit pname version;
    sha256 = "sha256-ICBhvcv4SqeY9Y34EQmxTTxlo4LA4hsBLa2QK73pu38=";
  };

  cargoHash = "sha256-k5cZhx9Q4yZILW9b3k9zOZNO5f2iqPTsrUsDu8mzLaE=";

  buildInputs = lib.optionals stdenv.isDarwin [ ];
}
