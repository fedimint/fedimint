{ stdenvNoCC, self, name, version, rustfmt, rust }:

stdenvNoCC.mkDerivation {
  pname = "${name}-cargo-fmt-check";
  inherit version;

  phases = [ "unpackPhase" "buildPhase" ];

  src = self;

  buildInputs = [ rustfmt ];

  buildPhase = ''
    ${rust}/bin/cargo fmt -- --check | tee $out
  '';
}
