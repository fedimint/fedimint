{
  lib,
  stdenv,
  fetchCrate,
  Security,
  rustPlatform,
}:
rustPlatform.buildRustPackage rec {
  pname = "rust-i18n-cli";
  version = "3.1.1";

  src = fetchCrate {
    inherit pname version;
    sha256 = "sha256-kQ4ZkGRrxrA5UOWSao2MdAPHKmNvqJWFML51X0l2eRc=";
  };

  cargoHash = "sha256-Wt4cI3uB7f5Sx9DR0Nrl8kdRf6Z4c93TOFLg5dssNWI=";

  buildInputs = lib.optionals stdenv.isDarwin [ Security ];
}
