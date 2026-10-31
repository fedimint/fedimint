{ pkgs }:
let
  python = pkgs.python3.withPackages (p: [
    p.pyelftools
    p.zstandard
  ]);
  tools = [
    python
    pkgs.llvmPackages_20.llvm
  ];
  runtime = pkgs.runCommand "debug-test-runtime" { } ''mkdir -p "$out/lib"'';
  source = pkgs.writeText "debug-test.c" ''
    __attribute__((section(".debug_allocated"), used))
    const char runtime_path[] = "${runtime}/lib";
    int main(void) { return runtime_path[0] != '/'; }
  '';
  fixture = pkgs.stdenv.mkDerivation {
    name = "container-debug-fixture";
    nativeBuildInputs = tools;
    dontUnpack = true;
    dontStrip = true;
    dontPatchELF = true;
    buildPhase = ''
      mkdir -p "$out/bin"
      # Keep the source basename out of STT_FILE in .strtab: this test covers
      # incidental DWARF paths, not removal of arbitrary non-debug references.
      cp ${source} fixture.c
      $CC -g -gdwarf-4 -fdebug-prefix-map="$PWD"=${source} \
        "$PWD/fixture.c" -Wl,-rpath,${runtime}/lib -o "$out/bin/plain"
      python ${./container-debug-references.py} prepare "$out/bin"
    '';
    installPhase = "chmod 555 $out/bin/*";
  };
  sanitized = (import ../container-package.nix { inherit pkgs; } fixture).overrideAttrs {
    # Check Nix's real hash scanner, not only our own string assertions.
    disallowedReferences = [ source ];
  };
in
pkgs.runCommand "container-debug-references-test"
  {
    nativeBuildInputs = tools;
  }
  ''
    python ${./container-debug-references.py} check \
      ${fixture}/bin ${sanitized}/bin ${source} ${../sanitize-debug-references.py}
    touch "$out"
  ''
