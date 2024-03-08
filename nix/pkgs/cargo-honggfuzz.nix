{ lib
, stdenv
, fetchCrate
, Security
, rustPlatform
}:
rustPlatform.buildRustPackage rec {
  pname = "honggfuzz";
  # last tagged version is far behind master
  version = "0.5.55";

  src = fetchCrate {
    inherit pname version;
    sha256 = "sha256-ICBhvcv4SqeY9Y34EQmxTTxlo4LA4hsBLa2QK73pu38=";
  };


  cargoHash = "sha256-NoO/ivfHLYeFlm/qUx32Fa2G+G/zob793XIqXQBFNws=";

  buildInputs = lib.optionals stdenv.isDarwin [ Security ];
}
