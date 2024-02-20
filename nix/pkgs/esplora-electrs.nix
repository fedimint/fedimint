{ lib
, stdenv
, llvmPackages_11
  # , clang11Stdenv
  # , makeRustPlatform
  # , buildPackages
, fetchFromGitHub
, rocksdb_6_23
, Security
, rustPlatform
}:
let
  rocksdb = rocksdb_6_23;
in
rustPlatform.buildRustPackage {
  pname = "esplora";
  # last tagged version is far behind master
  version = "20230218";

  src = fetchFromGitHub {
    # original:
    # owner = "Blockstream";
    # repo = "electrs";
    # rev = "adedee15f1fe460398a7045b292604df2161adc0";
    # hash = "sha256-KnN5C7wFtDF10yxf+1dqIMUb8Q+UuCz4CMQrUFAChuA=";

    # pre-allocation size patch:
    owner = "dpc";
    repo = "esplora-electrs";
    rev = "8186331b7ca33668d838dab91e2dc52c388ac689";
    hash = "sha256-D+ZdtZ57RoQsqebW0f2KsWz5/Di4Joy6walqGvGm/4o=";
  };


  cargoLock = {
    lockFile = ./esplora-electrs.Cargo.lock;

    outputHashes = {
      "electrum-client-0.8.0" = "sha256-HDRdGS7CwWsPXkA1HdurwrVu4lhEx0Ay8vHi08urjZ0=";
    };
  };

  # needed for librocksdb-sys
  nativeBuildInputs = [ rustPlatform.bindgenHook ];

  # https://stackoverflow.com/questions/76443280/rust-bindgen-causes-a-is-not-a-valid-ident-error-on-build
  preBuild = ''
    export LIBCLANG_PATH="${llvmPackages_11.libclang.lib}/lib"
  '';

  # link rocksdb dynamically
  ROCKSDB_INCLUDE_DIR = "${rocksdb}/include";
  ROCKSDB_LIB_DIR = "${rocksdb}/lib";

  buildInputs = lib.optionals stdenv.isDarwin [ Security ];

  # rename to avoid a name conflict with other electrs package
  postInstall = ''
    mv $out/bin/electrs $out/bin/esplora
  '';
}
