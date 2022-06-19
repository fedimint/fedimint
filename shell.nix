{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/57622cb817210146b379adbbd036d3da0d1f367c.tar.gz") {}}:

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
    procps
  ];
  OPENSSL_DIR = "${pkgs.openssl.dev}";
  OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
}

