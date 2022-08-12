#!/bin/bash

# Checks to run before opening a PR, should be run from minimint source root dir
# See tests/README.md for information on setting up Bitcoin / Lightning so the integration tests can complete

set -e

cargo fmt --all
cargo clippy --lib --bins --tests --examples --workspace -- -D warnings

export MINIMINT_TEST_REAL=0
cargo test

export MINIMINT_TEST_REAL=1
./scripts/rust-tests.sh
./scripts/cli-test.sh
./scripts/clientd-tests.sh
sleep 3

echo "CLI test exit status $?"