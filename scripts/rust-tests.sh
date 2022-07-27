#!/usr/bin/env bash
# Runs the all the Rust integration tests

set -euxo pipefail
export RUST_LOG=info

source ./scripts/build.sh
source ./scripts/setup-tests.sh #sources lib.sh

export MINIMINT_TEST_REAL=1
cargo test --release -p minimint-tests -- --test-threads=1