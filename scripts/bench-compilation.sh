#!/usr/bin/env bash

set -euo pipefail

on_error() {
  >&2 echo "Error! Results might be invalid."
}
trap on_error ERR

root="$(git rev-parse --show-toplevel)"

# Use a custom target dir, not to interfere
export CARGO_BUILD_TARGET_DIR="${root}/target-comp-bench"

# Disable sccache
unset RUSTC_WRAPPER

cargo fetch

rm -Rf "$CARGO_BUILD_TARGET_DIR"

nix run nixpkgs#neofetch -- --stdout
echo "Date: $(date +%Y-%m-%d)"
echo "Commit: $(git rev-parse --short HEAD)"

echo "Dev full:"
time cargo build -q 2>/dev/null 1>/dev/null

echo ""
echo "Dev incremental:"
touch fedimint-core/src/lib.rs
time cargo build -q 2>/dev/null 1>/dev/null

echo ""
echo "Release full:"
time cargo build -q --release 2>/dev/null 1>/dev/null

echo ""
echo "Release incremental:"
touch fedimint-core/src/lib.rs
time cargo build -q --release 2>/dev/null 1>/dev/null

rm -Rf "$CARGO_BUILD_TARGET_DIR"

>&2 echo "Success. Feel free to post on https://github.com/fedimint/fedimint/wiki/Benchmark-compilation-times"
