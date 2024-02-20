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

mkdir -p "${release_dir}"


>&2 echo "Building..."
for out in fedimint-pkgs gateway-pkgs ; do
  nix build "git+file:.?ref=refs/tags/${tag}#${out}"
  cp -f result/bin/* "${release_dir}/"
done


>&2 echo "Checksumming..."
( cd "${release_dir_base}"; sha256sum -- "${prefix}"/* ) > "${sha256sum_path}"


>&2 echo "Signinig..."
if [ -z "${GPG_SIGNING_KEY:-}" ]; then
  echo >&2 "GPG_SIGNING_KEY not set, will use default key"
fi

gpg --sign --detach-sign -a \
  ${GPG_SIGNING_KEY:+--local-user ${GPG_SIGNING_KEY}} \
  --output - \
  "${sha256sum_path}" >> "${sha256sum_path}.asc"
