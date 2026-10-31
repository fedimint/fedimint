{ pkgs }:
let
  python = pkgs.buildPackages.python3.withPackages (p: [
    p.pyelftools
    p.zstandard
  ]);
in
package:
pkgs.runCommand "${package.pname or package.name}-container"
  {
    nativeBuildInputs = [
      python
      pkgs.buildPackages.llvmPackages_20.llvm
    ];
  }
  ''
    cp -a ${package} "$out"
    # Keep the ordinary package (and its source paths) unchanged. Sanitize every
    # bundled executable, not just the container's entry point.
    find "$out/bin" -type f -exec \
      python ${./sanitize-debug-references.py} '{}' +
  ''
