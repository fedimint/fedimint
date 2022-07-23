#!/usr/bin/env bash
# Runs the all the Rust integration tests

set -euxo pipefail
export RUST_LOG=info

source ./scripts/build.sh
source ./scripts/setup-tests.sh

export fedimint_TEST_REAL=1
cargo test --release -p fedimint-tests -- --test-threads=1