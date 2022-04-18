{ stdenvNoCC, self, name, version, nixpkgs-fmt }:

stdenvNoCC.mkDerivation {
  pname = "${name}-check";
  inherit version;

  phases = [ "unpackPhase" "buildPhase" ];

  src = self;

  buildPhase = ''
    ${nixpkgs-fmt}/bin/nixpkgs-fmt --check **/*.nix *.nix | tee $out
  '';
}
