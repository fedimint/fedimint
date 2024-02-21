final: prev: {
  # Note: shell script adding DYLD_FALLBACK_LIBRARY_PATH because of: https://github.com/nextest-rs/nextest/issues/962
  cargo-nextest = final.writeShellScriptBin "cargo-nextest" "exec env DYLD_FALLBACK_LIBRARY_PATH=\"$(dirname $(${final.which}/bin/which rustc))/../lib\" ${prev.cargo-nextest}/bin/cargo-nextest \"$@\"";
}
