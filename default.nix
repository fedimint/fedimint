with import <nixpkgs>{};

let
    pkgs = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/57622cb817210146b379adbbd036d3da0d1f367c.tar.gz") {};
    sources = import ./nix/sources.nix;
    naersk = pkgs.callPackage sources.naersk {};
in naersk.buildPackage {
  pname = "minimint";
  version = "ci";
  src = builtins.filterSource (p: t: lib.cleanSourceFilter p t && baseNameOf p != "target") ./.;
  buildInputs = [
      pkgs.openssl
      pkgs.pkg-config
      pkgs.perl
  ];

gitSubmodules = true;
  
}