#!/usr/bin/env bash
# Runs the all the Rust integration tests

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info,timing=debug}"

source scripts/build.sh ""

>&2 echo "### Setting up tests"

# Convert RUST_LOG to lowercase
# if RUST_LOG is none, don't show output of test setup
if [ "${RUST_LOG,,}" = "none" ]; then
  devimint external-daemons >/dev/null &
  echo $! >> $FM_PID_FILE
else
  devimint external-daemons &
  echo $! >> $FM_PID_FILE
fi

STATUS=$(devimint wait)
if [ "$STATUS" = "ERROR" ]
then
    echo "base daemons didn't start correctly"
    exit 1
fi

eval "$(devimint env)"
>&2 echo "### Setting up tests - complete"

env RUST_BACKTRACE=1 cargo test -p fedimint-ln-server ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -- --test-threads=$(($(nproc) * 2)) "$@"

export FM_TEST_USE_REAL_DAEMONS=1

if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "bitcoind" ]; then
  >&2 echo "### Testing against bitcoind"
  env RUST_BACKTRACE=1 cargo test -p ln-gateway ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -- --test-threads=$(($(nproc) * 2)) "$@"
  env RUST_BACKTRACE=1 cargo test -p fedimint-ln-tests ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -- --test-threads=$(($(nproc) * 2)) "$@"
  env RUST_BACKTRACE=1 cargo test -p fedimint-dummy-tests ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -- --test-threads=$(($(nproc) * 2)) "$@"
  env RUST_BACKTRACE=1 cargo test -p fedimint-mint-tests ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -- --test-threads=$(($(nproc) * 2)) "$@"
  env RUST_BACKTRACE=1 cargo test -p fedimint-wallet-tests ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -- --test-threads=$(($(nproc) * 2)) "$@"
  env RUST_BACKTRACE=1 cargo test -p fedimint-tests ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -- --test-threads=$(($(nproc) * 2)) "$@"
  >&2 echo "### Testing against bitcoind - complete"
fi

# Switch to electrum and run wallet tests
export FM_BITCOIN_RPC_KIND="electrum"
export FM_BITCOIN_RPC_URL="tcp://127.0.0.1:50001"

if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "electrs" ]; then
  >&2 echo "### Testing against electrs"
  env RUST_BACKTRACE=1 cargo test -p fedimint-wallet-tests ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -- --test-threads=$(($(nproc) * 2)) "$@"
  env RUST_BACKTRACE=1 cargo test -p fedimint-tests wallet ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -- --test-threads=$(($(nproc) * 2)) "$@"
  >&2 echo "### Testing against electrs - complete"
fi

# Switch to esplora and run wallet tests
export FM_BITCOIN_RPC_KIND="esplora"
export FM_BITCOIN_RPC_URL="http://127.0.0.1:50002"
if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "esplora" ]; then
  >&2 echo "### Testing against esplora"
  env RUST_BACKTRACE=1 cargo test -p fedimint-wallet-tests ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -- --test-threads=$(($(nproc) * 2)) "$@"
  env RUST_BACKTRACE=1 cargo test -p fedimint-tests wallet ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -- --test-threads=$(($(nproc) * 2)) "$@"
  >&2 echo "### Testing against esplora - complete"
fi

echo "fm success: rust-tests"
