#!/bin/bash

# Checks to run before opening a PR, should be run from fedimint source root dir
# See tests/README.md for information on setting up Bitcoin / Lightning so the integration tests can complete

set -e

cargo fmt --all
cargo clippy --fix --lib --bins --tests --examples --workspace --allow-dirty

export FM_TEST_DISABLE_MOCKS=0
cargo test

if [ "$1" == "nix" ]; then
  nix-shell --run ./scripts/cli-test.sh
  nix-shell --run ./scripts/rust-tests.sh
  nix-shell --run ./scripts/clientd-tests.sh
fi

echo "Tests succeeded"