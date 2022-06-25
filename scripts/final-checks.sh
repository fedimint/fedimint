#!/bin/bash

# Checks to run before opening a PR, should be run from minimint source root dir
# See tests/README.md for information on setting up Bitcoin / Lightning so the integration tests can complete

set -e

cargo fmt --all
cargo clippy --lib --bins --tests --examples --workspace -- -D warnings

export MINIMINT_TEST_REAL=0
cargo test

export MINIMINT_TEST_REAL=1
export MINIMINT_TEST_DIR=$PWD/it/
cargo test -p minimint-tests -- --test-threads=1
