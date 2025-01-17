#!/usr/bin/env bash

set -euo pipefail


export CARGO_BUILD_TARGET_DIR=./target

if [ -z "${CI:-}" ]; then
  >&2 echo "This test is meant to run in the CI, and will nuke your target dir. Set CI=true to confirm."
  exit 1
fi

nix build -L ".#${CARGO_PROFILE}.workspaceBuild"
rm -rf "$CARGO_BUILD_TARGET_DIR"


# don't waste space, clean up after completing
on_exit() {
  rm -rf "$CARGO_BUILD_TARGET_DIR"
}
trap on_exit EXIT

mkdir -p "${CARGO_BUILD_TARGET_DIR}"

>&2 echo "Extracting target build dir from Nix build..."
for target_zstd in result/target.tar.zst.prev result/target.tar.zst ; do
  nix run nixpkgs#zstd -- -d "$(realpath "$target_zstd")" --stdout | \
      nix run nixpkgs#gnutar -- -x -C "${CARGO_BUILD_TARGET_DIR}"
done

# cargo would want to rebuild everything because the Nix building system
# is using slightly different paths etc, but we know for a fact
# that we've already built everything in this version
env \
  SKIP_CARGO_BUILD=1 \
  CARGO_DENY_COMPILATION=1 \
  "$@"
