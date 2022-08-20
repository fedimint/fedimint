#!/usr/bin/env bash
# Runs the all the Rust integration tests

set -euxo pipefail
export RUST_LOG=info

source ./scripts/setup-tests.sh

export FM_TEST_DISABLE_MOCKS=1
cargo test --release -p fedimint-tests -- --test-threads=1