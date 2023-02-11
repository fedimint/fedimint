#!/usr/bin/env bash
# Runs the all the Rust integration tests

set -euxo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source ./scripts/setup-tests.sh ""

export FM_TEST_DISABLE_MOCKS=1
env RUST_BACKTRACE=1 cargo test -p fedimint-tests -- --test-threads=$(($(nproc) * 2)) "$@"
