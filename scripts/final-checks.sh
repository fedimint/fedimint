#!/bin/bash

# Checks to run before opening a PR, should be run from minimint source root dir
# See tests/README.md for information on setting up Bitcoin / Lightning so the integration tests can complete

set -e

cargo +nightly clippy --lib --bins --tests --examples --workspace -- -D warnings
cargo fmt --all

export MINIMINT_TEST_REAL=0
cargo test

export MINIMINT_TEST_REAL=1
export MINIMINT_TEST_DIR=$PWD/it/
cargo test -p minimint -- --test-threads=1