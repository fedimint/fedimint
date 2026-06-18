#!/usr/bin/env bash
set -euo pipefail

flake_ref="${1:-.}"
root_dir="${NIX_FLAKE_INPUT_GCROOT_DIR:-${RUNNER_TEMP:-$PWD}/nix-flake-input-gcroots}"

mkdir -p "$root_dir"

archive_json="$(mktemp)"
paths_expr="$(mktemp "${TMPDIR:-/tmp}/nix-flake-input-paths.XXXXXX.nix")"
trap 'rm -f "$archive_json" "$paths_expr"' EXIT

nix flake archive --json "$flake_ref" > "$archive_json"

cat > "$paths_expr" <<EOF_NIX
let
  archive = builtins.fromJSON (builtins.readFile $archive_json);

  collectPaths = value:
    if builtins.isAttrs value then
      (if value ? path && builtins.isString value.path && builtins.match "/nix/store/.*" value.path != null then
        [ value.path ]
      else
        [ ])
      ++ builtins.concatLists (map collectPaths (builtins.attrValues value))
    else if builtins.isList value then
      builtins.concatLists (map collectPaths value)
    else
      [ ];
in
  builtins.concatStringsSep "\\n" (collectPaths archive)
EOF_NIX

nix eval --raw --file "$paths_expr" \
  | sort -u \
  | while IFS= read -r path; do
      [ -n "$path" ] || continue
      root_name="$(basename "$path")"
      nix-store --add-root "$root_dir/$root_name" --indirect --realise "$path" >/dev/null
    done

root_count=0
for root in "$root_dir"/*; do
  if [ -L "$root" ]; then
    root_count=$((root_count + 1))
  fi
done
echo "Pinned $root_count Nix flake input store paths under $root_dir"
