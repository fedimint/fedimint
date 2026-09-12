{
  lib,
  stdenv,
  llvmPackages,
  fetchFromGitHub,
  rocksdb,
  rustPlatform,
}:
rustPlatform.buildRustPackage {
  pname = "esplora";
  # The last tagged version is far behind the `new-index` branch that Esplora
  # actually ships from, so we track a revision of that branch instead.
  version = "20260819";

  # This used to pin a personal fork carrying a single patch, shrinking RocksDB's
  # write buffer. Upstream has since exposed that as `--db-write-buffer-size-mb`,
  # which devimint now passes, so the fork is gone and we build upstream
  # unmodified. Bumping this is just a revision and a hash.
  src = fetchFromGitHub {
    owner = "Blockstream";
    repo = "electrs";
    rev = "b7ae3356e3a77b33db96129d61a1b70b8113700e";
    hash = "sha256-5FUdCGGxVpMCY7YASu2PGpGeCUotEhPzvD6RXLBVSNQ=";
  };

  doCheck = false;

  cargoLock = {
    lockFile = ./esplora-electrs.Cargo.lock;

    outputHashes = {
      "electrum-client-0.8.0" = "sha256-HDRdGS7CwWsPXkA1HdurwrVu4lhEx0Ay8vHi08urjZ0=";
      "electrumd-0.1.0" = "sha256-Js4gc/XvokWpPGQGPnWcak2Bt6DNQcosT3CkY841z2c=";
      "jsonrpc-0.12.0" = "sha256-lSNkkQttb8LnJej4Vfe7MrjiNPOuJ5A6w5iLstl9O1k=";
    };
  };

  # needed for librocksdb-sys
  nativeBuildInputs = [ rustPlatform.bindgenHook ];

  # https://stackoverflow.com/questions/76443280/rust-bindgen-causes-a-is-not-a-valid-ident-error-on-build
  preBuild = ''
    export LIBCLANG_PATH="${llvmPackages.libclang.lib}/lib"
  '';

  # Link rocksdb dynamically against whatever nixpkgs provides, rather than
  # pinning a version that has to be bumped in step with the crate.
  ROCKSDB_INCLUDE_DIR = "${rocksdb}/include";
  ROCKSDB_LIB_DIR = "${rocksdb}/lib";

  # rename to avoid a name conflict with other electrs package
  postInstall = ''
    mv $out/bin/electrs $out/bin/esplora
  '';
}
