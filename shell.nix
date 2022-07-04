let
  nix-pinned = builtins.fetchTarball {
    name = "nixos-22.05";
    url = "https://github.com/NixOS/nixpkgs/archive/bd95ace2d31564c0caceda68a8c2ec1b97f7116e.tar.gz";
  };
in
{ pkgs ? import (nix-pinned) {}}:
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
    bc
    clang
    openssl
    pkg-config
    perl
    clippy
    rustfmt
    rustc
    cargo
    rust-analyzer
    bitcoind-patch-darwin
    clightning-dev
    jq
    procps
    tmux
    tmuxinator
  ] ++ lib.optionals stdenv.isDarwin [
    libiconv
    darwin.apple_sdk.frameworks.Security
  ];
  OPENSSL_DIR = "${pkgs.openssl.dev}";
  OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
  shellHook = ''
    # filter out global cargo installation so it doesn't interfere
    PATH="$(echo $PATH | sed "s/:[^:]*\.cargo[^:]*//g")"
  '';
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
}

