{ pkgs ? import <nixpkgs> {}}:

pkgs.mkShell {
  packages = with pkgs; [
    openssl
    pkg-config
    perl
    rustc
    cargo
    rust-analyzer
    bitcoin
    clightning
    jq
  ];

  RUST_SRC_PATH = "${pkgs.rust-src}/lib/rustlib/src/rust/library";
  OPENSSL_DIR = "${pkgs.openssl.dev}";
  OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
}

