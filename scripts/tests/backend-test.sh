#!/usr/bin/env bash
# Runs the all the Rust integration tests

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info,timing=debug}"

source scripts/lib.sh
source scripts/build.sh ""

>&2 echo "### Setting up tests"

# Convert RUST_LOG to lowercase
# if RUST_LOG is none, don't show output of test setup
if [ "${RUST_LOG,,}" = "none" ]; then
  devimint external-daemons >/dev/null &
else
  devimint external-daemons &
fi
auto_kill_last_cmd external-daemons

STATUS=$(devimint wait)
if [ "$STATUS" = "ERROR" ]
then
    echo "base daemons didn't start correctly"
    exit 1
fi

export RUST_BACKTRACE=1 

eval "$(devimint env)"
>&2 echo "### Setting up tests - complete"

export FM_TEST_USE_REAL_DAEMONS=1

if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "bitcoind" ]; then
  >&2 echo "### Testing against bitcoind"

  # Note: Ideally `-E` flags can be used together, but that seems to trigger lots of problems
  cargo nextest run --locked --workspace --all-targets ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --test-threads=$(($(nproc) * 2)) \
    -E 'package(fedimint-dummy-tests)'
  cargo nextest run --locked --workspace --all-targets ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --test-threads=$(($(nproc) * 2)) \
    -E 'package(fedimint-mint-tests)'
  cargo nextest run --locked --workspace --all-targets ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --test-threads=$(($(nproc) * 2)) \
    -E 'package(fedimint-wallet-tests)'
  cargo nextest run --locked --workspace --all-targets ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --test-threads=$(($(nproc) * 2)) \
    -E 'package(fedimint-ln-tests)'
  cargo nextest run --locked --workspace --all-targets ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --test-threads=1 \
    -E 'package(ln-gateway)'
  >&2 echo "### Testing against bitcoind - complete"
fi

# Switch to electrum and run wallet tests
export FM_BITCOIN_RPC_KIND="electrum"
export FM_BITCOIN_RPC_URL="tcp://127.0.0.1:$FM_PORT_ELECTRS"

if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "electrs" ]; then
  >&2 echo "### Testing against electrs"
  cargo nextest run --locked --workspace --all-targets ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --test-threads=$(($(nproc) * 2)) \
    -E 'package(fedimint-wallet-tests)'
  >&2 echo "### Testing against electrs - complete"
fi

# Switch to esplora and run wallet tests
export FM_BITCOIN_RPC_KIND="esplora"
export FM_BITCOIN_RPC_URL="http://127.0.0.1:$FM_PORT_ESPLORA"

if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "esplora" ]; then
  >&2 echo "### Testing against esplora"
  cargo nextest run --locked --workspace --all-targets ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --test-threads=$(($(nproc) * 2)) \
    -E 'package(fedimint-wallet-tests)'
  >&2 echo "### Testing against esplora - complete"
fi

echo "fm success: rust-tests"
