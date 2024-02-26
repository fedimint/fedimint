{ pkgs }: {
  env = {
    OPENSSL_DIR = "${pkgs.openssl.dev}";
    LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
  };
  deps = [
    pkgs.direnv
    pkgs.just
    pkgs.gcc
    pkgs.mold
    pkgs.rustc
    pkgs.rustfmt
    pkgs.cargo
    pkgs.cargo-edit
    pkgs.rust-analyzer
    pkgs.clang
    pkgs.libclang.lib
    pkgs.lld
    pkgs.pkg-config
    pkgs.openssl
    pkgs.protobuf
    pkgs.bitcoind
  ];
}
