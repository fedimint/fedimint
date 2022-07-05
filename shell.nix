{ pkgs ? import <nixpkgs> {}}:
let
  clightning-dev = pkgs.clightning.overrideAttrs (oldAttrs: {
    configureFlags = [ "--enable-developer" "--disable-valgrind" ];
  } // pkgs.lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
    NIX_CFLAGS_COMPILE="-Wno-stringop-truncation";
  });
  bitcoind-patch-darwin = pkgs.bitcoind.overrideAttrs (oldAttrs: {
    doCheck = !(pkgs.stdenv.isDarwin && pkgs.stdenv.isAarch64);
  });
in
pkgs.mkShell {
  packages = with pkgs; [
    openssl
    pkg-config
    perl
    rustc
    cargo
    rust-analyzer
    bitcoind-patch-darwin
    clightning-dev
    jq
    procps
  ] ++ lib.optionals stdenv.isDarwin [
    libiconv
    darwin.apple_sdk.frameworks.Security
  ];
  OPENSSL_DIR = "${pkgs.openssl.dev}";
  OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
}

