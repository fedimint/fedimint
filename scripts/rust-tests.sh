#!/usr/bin/env bash
# Runs the all the Rust integration tests

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info,timing=debug}"


>&2 echo "### Setting up tests"
# Convert RUST_LOG to lowercase
# if RUST_LOG is none, don't show output of test setup
if [ "${RUST_LOG,,}" = "none" ]; then
  source ./scripts/setup-tests.sh "" >/dev/null
else
  set -x
  source ./scripts/setup-tests.sh ""
fi
>&2 echo "### Setting up tests - complete"

export FM_TEST_USE_REAL_DAEMONS=1

if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "bitcoind" ]; then
  >&2 echo "### Testing against bitcoind"
  env RUST_BACKTRACE=1 cargo test -p fedimint-tests -- --test-threads=16 "$@"
  >&2 echo "### Testing against bitcoind - complete"
fi

# Switch to electrum and run wallet tests
unset FM_BITCOIND_RPC
export FM_ELECTRUM_RPC="tcp://127.0.0.1:50001"

if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "electrs" ]; then
  >&2 echo "### Testing against electrs"
  env RUST_BACKTRACE=1 cargo test -p fedimint-tests wallet -- --test-threads=$(($(nproc) * 2)) "$@"
  >&2 echo "### Testing against electrs - complete"
fi

# Switch to esplora and run wallet tests
unset FM_ELECTRUM_RPC
export FM_ESPLORA_RPC="http://127.0.0.1:50002"
if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "esplora" ]; then
  >&2 echo "### Testing against esplora"
  env RUST_BACKTRACE=1 cargo test -p fedimint-tests wallet -- --test-threads=$(($(nproc) * 2)) "$@"
  >&2 echo "### Testing against esplora - complete"
fi

echo "fm success: rust-tests"
