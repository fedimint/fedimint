#!/usr/bin/env bash
# Run from the repository root: bash nix/tests/source-filter.sh
set -euo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/base/.agents/skills/existing" "$tmp/base/src"
printf 'skill\n' > "$tmp/base/.agents/skills/existing/SKILL.md"
printf 'fn main() {}\n' > "$tmp/base/src/main.rs"
printf '[workspace]\n' > "$tmp/base/Cargo.toml"

for variant in skill-edit skill-add rust-edit cargo-edit sibling; do
  cp -R "$tmp/base" "$tmp/$variant"
done
printf 'changed skill\n' > "$tmp/skill-edit/.agents/skills/existing/SKILL.md"
mkdir -p "$tmp/skill-add/.agents/skills/new/nested"
printf 'new skill\n' > "$tmp/skill-add/.agents/skills/new/SKILL.md"
# Even files matching build-input regexes must stay out of the skill subtree.
printf 'skill example\n' > "$tmp/skill-add/.agents/skills/new/nested/example.rs"
printf 'skill example\n' > "$tmp/skill-add/.agents/skills/new/Cargo.toml"
printf 'fn main() { println!("changed"); }\n' > "$tmp/rust-edit/src/main.rs"
printf '[workspace]\nresolver = "2"\n' > "$tmp/cargo-edit/Cargo.toml"
mkdir -p "$tmp/sibling/.agents/skills-other"
printf 'fn sibling() {}\n' > "$tmp/sibling/.agents/skills-other/keep.rs"

export SOURCE_FILTER_FIXTURES="$tmp"
nix eval --impure --json --expr '
  let
    flake = builtins.getFlake (toString ./.);
    filter = import ./nix/filter-source.nix { lib = flake.inputs.nixpkgs.lib; };
    root = builtins.getEnv "SOURCE_FILTER_FIXTURES";
    # Exercise the shared filter with both Rust and Cargo build-input patterns.
    source = variant: toString (filter [
      ".*\\.rs" "Cargo\\.toml" ".*/Cargo\\.toml"
    ] (builtins.path { path = root + "/" + variant; name = "fixture"; }));
    base = source "base";
  in
  assert base == source "skill-edit";
  assert base == source "skill-add";
  assert base != source "rust-edit";
  assert base != source "cargo-edit";
  assert base != source "sibling";
  assert !(builtins.pathExists (base + "/.agents/skills"));
  assert builtins.pathExists (base + "/src/main.rs");
  assert builtins.pathExists (base + "/Cargo.toml");
  "source filter regression checks passed"
'
