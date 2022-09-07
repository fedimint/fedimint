#!/usr/bin/env bash

# Checks to run before opening a PR, should be run from fedimint source root dir
# See tests/README.md for information on setting up Bitcoin / Lightning so the integration tests can complete

set -e

cargo clippy --fix --lib --bins --tests --examples --workspace --allow-dirty
nix develop --ignore-environment --extra-experimental-features nix-command --extra-experimental-features flakes .#lint --command ./misc/git-hooks/pre-commit

export FM_TEST_DISABLE_MOCKS=0
cargo test --release

if [ "$1" == "nix" ]; then
  nix-shell --run ./scripts/cli-test.sh
  nix-shell --run ./scripts/rust-tests.sh
  nix-shell --run ./scripts/clientd-tests.sh
fi

echo "Tests succeeded"
