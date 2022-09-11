{ pkgs }: {
  deps = [
    pkgs.gcc
    pkgs.mold
    pkgs.rustc
    pkgs.rustfmt
    pkgs.cargo
    pkgs.cargo-edit
    pkgs.rust-analyzer
    pkgs.clang
    pkgs.libclang.lib
    pkgs.pkg-config
    pkgs.openssl
    pkgs.nix
  ];
}
