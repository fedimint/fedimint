with import <nixpkgs>{};

let
    pkgs = import <nixpkgs> {};
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
  shellHook =
  ''
    SRC_DIR="$( cd -- "$( dirname -- "''${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
    cp -r $out/target $SRC_DIR/target
  '';
}