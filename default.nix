with import <nixpkgs>{};

let
    pkgs = import <nixpkgs> {};
    sources = import ./nix/sources.nix;
    naersk = pkgs.callPackage sources.naersk {};
in naersk.buildPackage {
  pname = "fedimint";
  version = "ci";
  src = builtins.filterSource (p: t: lib.cleanSourceFilter p t && baseNameOf p != "target") ./.;
  buildInputs = [
      pkgs.openssl
      pkgs.pkg-config
      pkgs.perl
  ];
gitSubmodules = true;
  
}