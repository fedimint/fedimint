#!/usr/bin/env bash

set -euo pipefail

source "scripts/_common.sh"

if [ -z "${1:-}" ]; then
  >&2 echo "First argument must be a tag (e.g. v0.2.2)"
fi

tag="$1"
system="$(nix-current-system)"
prefix="${tag}-${system}"
release_dir_base="releases/bins"
release_dir="${release_dir_base}/${prefix}"
sha256sum_path="releases/${prefix}.SHA256SUMS"

if ! git rev-parse --verify "refs/tags/$tag" 1>/dev/null 2>/dev/null; then
  >&2 echo "Can't find tag: $tag"
  exit 1
fi

>&2 echo "Building..."

# TODO: add gateway-cln-extension once available as an output
for bin in fedimintd fedimint-cli fedimint-dbtool gateway-cli gatewayd ; do
  # We need to use rev= , see https://github.com/NixOS/nix/issues/11266
  # NOTE: '^{commit}' is not a mistake, but git rev-parse syntaxh
  rev="$(git rev-parse "${tag}^{commit}")"
  repo="git+file:${REPO_ROOT}?rev=${rev}"
  out="$repo#${bin}"
  nix build "$out"
  mkdir -p "${release_dir}/nixos"
  cp -f result/bin/* "${release_dir}/nixos/"

  # skip bundles on Darwin (not supported)
  if [[ "$system" != *"-darwin" ]]; then
    nix bundle --bundler "$repo" "$out" -o result
    cp -f -L result "${release_dir}/$bin"
  fi
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
