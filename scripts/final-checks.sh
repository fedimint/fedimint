#!/bin/bash

# Checks to run before opening a PR, should be run from fedimint source root dir
# See tests/README.md for information on setting up Bitcoin / Lightning so the integration tests can complete

set -e

cargo fmt --all
cargo clippy --lib --bins --tests --examples --workspace -- -D warnings

export fedimint_TEST_REAL=0
cargo test

export fedimint_TEST_REAL=1
./scripts/rust-tests.sh
./scripts/cli-test.sh
sleep 3

echo "CLI test exit status $?"