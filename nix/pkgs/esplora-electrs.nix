{
  lib,
  stdenv,
  llvmPackages,
  fetchFromGitHub,
  rocksdb_8_3,
  rustPlatform,
}:
let
  rocksdb = rocksdb_8_3;
in
rustPlatform.buildRustPackage {
  pname = "esplora";
  # last tagged version is far behind master
  version = "20241009";

  src = fetchFromGitHub {
    # original:
    # owner = "Blockstream";
    # repo = "electrs";
    # rev = "adedee15f1fe460398a7045b292604df2161adc0";
    # hash = "sha256-KnN5C7wFtDF10yxf+1dqIMUb8Q+UuCz4CMQrUFAChuA=";

    # pre-allocation size patch:
    owner = "dpc";
    repo = "esplora-electrs";
    rev = "9339bfaf40b896f9d0b9ee945edc44ef49f99d2b";
    hash = "sha256-4PL+dvdUOTlX0IcpkcSxZ7TchsCI4fI8OmsFmwrtPHo=";
  };

  doCheck = false;

  cargoLock = {
    lockFile = ./esplora-electrs.Cargo.lock;

    outputHashes = {
      "electrum-client-0.8.0" = "sha256-HDRdGS7CwWsPXkA1HdurwrVu4lhEx0Ay8vHi08urjZ0=";
      "electrumd-0.1.0" = "sha256-QsoMD2uVDEITuYmYItfP6BJCq7ApoRztOCs7kdeRL9Y=";
      "jsonrpc-0.12.0" = "sha256-lSNkkQttb8LnJej4Vfe7MrjiNPOuJ5A6w5iLstl9O1k=";
    };
  };

  # needed for librocksdb-sys
  nativeBuildInputs = [ rustPlatform.bindgenHook ];

  # https://stackoverflow.com/questions/76443280/rust-bindgen-causes-a-is-not-a-valid-ident-error-on-build
  preBuild = ''
    export LIBCLANG_PATH="${llvmPackages.libclang.lib}/lib"
  '';

  # link rocksdb dynamically
  ROCKSDB_INCLUDE_DIR = "${rocksdb}/include";
  ROCKSDB_LIB_DIR = "${rocksdb}/lib";

  # rename to avoid a name conflict with other electrs package
  postInstall = ''
    mv $out/bin/electrs $out/bin/esplora
  '';
}
