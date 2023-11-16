#!/usr/bin/env bash
# Runs the all the Rust integration tests

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info,timing=debug}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker


function run_tests() {
  set -euo pipefail

  >&2 echo "### Starting tests"

  export FM_TEST_USE_REAL_DAEMONS=1
  export RUST_BACKTRACE=1
  TEST_ARGS="${TEST_ARGS:-}"
  TEST_ARGS_SERIALIZED="${TEST_ARGS:-$TEST_ARGS --test-threads=1}"
  TEST_ARGS_THREADED="${TEST_ARGS:-$TEST_ARGS --test-threads=$(($(nproc) * 2))}"


  if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "bitcoind" ]; then
    >&2 echo "### Testing against bitcoind"

    # Note: Ideally `-E` flags can be used together, but that seems to trigger lots of problems
    cargo nextest run --locked --workspace --all-targets \
      ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
      ${TEST_ARGS_THREADED} \
      -E 'package(fedimint-dummy-tests)'
    cargo nextest run --locked --workspace --all-targets \
      ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
      ${TEST_ARGS_THREADED} \
      -E 'package(fedimint-mint-tests)'
    cargo nextest run --locked --workspace --all-targets \
      ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
      ${TEST_ARGS_THREADED} \
      -E 'package(fedimint-wallet-tests)'
    cargo nextest run --locked --workspace --all-targets \
      ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
      ${TEST_ARGS_SERIALIZED} \
      -E 'package(fedimint-ln-tests)'
    cargo nextest run --locked --workspace --all-targets \
      ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
      ${TEST_ARGS_SERIALIZED} 'package(ln-gateway)'
    >&2 echo "### Testing against bitcoind - complete"
  fi

  # Switch to electrum and run wallet tests
  export FM_BITCOIN_RPC_KIND="electrum"
  export FM_BITCOIN_RPC_URL="tcp://127.0.0.1:$FM_PORT_ELECTRS"

  if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "electrs" ]; then
    >&2 echo "### Testing against electrs"
    cargo nextest run --locked --workspace --all-targets \
      ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
      ${TEST_ARGS_THREADED} \
      -E 'package(fedimint-wallet-tests)'
    >&2 echo "### Testing against electrs - complete"
  fi

  # Switch to esplora and run wallet tests
  export FM_BITCOIN_RPC_KIND="esplora"
  export FM_BITCOIN_RPC_URL="http://127.0.0.1:$FM_PORT_ESPLORA"

  if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "esplora" ]; then
    >&2 echo "### Testing against esplora"
    cargo nextest run --locked --workspace --all-targets \
      ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
      ${TEST_ARGS_THREADED} \
      -E 'package(fedimint-wallet-tests)'
    >&2 echo "### Testing against esplora - complete"
  fi

}
export -f run_tests

devimint external-daemons --exec bash -c 'run_tests'

echo "fm success: rust-tests"
