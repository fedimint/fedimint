default:
  @just --list

check:
  cargo check --all --all-targets

build:
  cargo build --all --all-targets

test: build
  cargo test

lint:
  env NO_STASH=true misc/git-hooks/pre-commit

clippy:
  cargo clippy --all --all-targets

format:
  cargo fmt --all
  nixpkgs-fmt $(echo **.nix)

tmuxinator:
  ./scripts/tmuxinator.sh
