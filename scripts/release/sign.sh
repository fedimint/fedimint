#!/usr/bin/env bash

set -euo pipefail

if [ -z "${1:-}" ]; then
  >&2 echo "First argument must be a tag (e.g. v0.2.2)"
fi

tag="$1"
system="$(nix eval --raw --impure --expr builtins.currentSystem)"
prefix="${tag}-${system}"
release_dir_base="releases/bins"
release_dir="${release_dir_base}/${prefix}"
sha256sum_path="releases/${prefix}.SHA256SUMS"


>&2 echo "Building..."

# TODO: add gateway-cln-extension once available as an output
for bin in fedimintd fedimint-cli fedimint-dbtool gateway-cli gatewayd ; do
  out="git+file:.?ref=refs/tags/${tag}#${bin}"
  nix build "$out"
  mkdir -p "${release_dir}/nixos"
  cp -f result/bin/* "${release_dir}/nixos/"

  # TODO: re-export pinned bundlers from our own flake, so they are pinned at the release time
  # and use the bundler exported in the release: '--bundler git+file:?ref/targs/'
  # TODO: switch back to upstream after https://github.com/matthewbauer/nix-bundle/pull/103 is available
  nix bundle --bundler "github:dpc/bundlers?branch=24-02-21-tar-deterministic&rev=e8aafe89a11ae0a5f3ce97d1d7d0fcfb354c79eb" "$out" -o result
  cp -f -L result "${release_dir}/$bin"
done

>&2 echo "Checksumming..."
( cd "${release_dir_base}"; find "${prefix}" -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum ) > "${sha256sum_path}"


>&2 echo "Signinig..."
if [ -z "${GPG_SIGNING_KEY:-}" ]; then
  echo >&2 "GPG_SIGNING_KEY not set, will use default key"
fi

gpg --sign --detach-sign -a \
  ${GPG_SIGNING_KEY:+--local-user ${GPG_SIGNING_KEY}} \
  --output - \
  "${sha256sum_path}" >> "${sha256sum_path}.asc"
