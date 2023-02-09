#!/usr/bin/env bash
# Runs the all the Rust integration tests

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

# Convert RUST_LOG to lowercase
# if RUST_LOG is none, don't show output of test setup
if [ "${RUST_LOG,,}" = "none" ]; then
  source ./scripts/setup-tests.sh "" >/dev/null
else
  set -x
  source ./scripts/setup-tests.sh ""
fi


export FM_TEST_DISABLE_MOCKS=1
env RUST_BACKTRACE=1 cargo test -p fedimint-tests "$@"
