#!/usr/bin/env bash
# Runs the all the Rust integration tests

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

function run_tests() {
  set -euo pipefail

  >&2 echo "### Starting tests"

  export FM_TEST_USE_REAL_DAEMONS=1
  export RUST_BACKTRACE=1
  export RUST_LIB_BACKTRACE=0
  TEST_ARGS="${TEST_ARGS:-}"
  TEST_ARGS_SERIALIZED="${TEST_ARGS:-$TEST_ARGS --test-threads=1}"
  TEST_ARGS_THREADED="${TEST_ARGS:-$TEST_ARGS --test-threads=$(($(nproc) * 2))}"


  if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "bitcoind" ]; then
    >&2 echo "### Testing against bitcoind"

    if [ -z "${FM_BITCOIND_TEST_ONLY:-}" ] || [ "${FM_BITCOIND_TEST_ONLY:-}" = "mint" ]; then
      cargo nextest run --locked --workspace --all-targets \
        ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
        ${TEST_ARGS_THREADED} \
        -E 'package(fedimint-mint-tests)'
    fi
    if [ -z "${FM_BITCOIND_TEST_ONLY:-}" ] || [ "${FM_BITCOIND_TEST_ONLY:-}" = "wallet" ]; then
      cargo nextest run --locked --workspace --all-targets \
        ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
        ${TEST_ARGS_THREADED} \
        -E 'package(fedimint-wallet-tests)'
    fi
    if [ -z "${FM_BITCOIND_TEST_ONLY:-}" ] || [ "${FM_BITCOIND_TEST_ONLY:-}" = "ln" ]; then
      cargo nextest run --locked --workspace --all-targets \
        ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
        ${TEST_ARGS_SERIALIZED} \
        -E 'package(fedimint-ln-tests)'
    fi
    if [ -z "${FM_BITCOIND_TEST_ONLY:-}" ] || [ "${FM_BITCOIND_TEST_ONLY:-}" = "lnv2" ]; then
      cargo nextest run --locked --workspace --all-targets \
        ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
        ${TEST_ARGS_SERIALIZED} \
        -E 'package(fedimint-lnv2-tests)'
    fi
    >&2 echo "### Testing against bitcoind - complete"
  fi

  if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "bitcoind-ln-gateway" ]; then
    >&2 echo "### Testing against bitcoind for ln-gateway"

    # since it's being ran serially, these tests take a while, so we split them into two
    # parts that test-ci-all runs in parallel

    if [ -z "${FM_BITCOIND_GW_TEST_ONLY:-}" ] || [ "${FM_BITCOIND_GW_TEST_ONLY:-}" = "gateway-client" ]; then
      cargo nextest run --locked --workspace --all-targets \
        ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
        ${TEST_ARGS_SERIALIZED} \
        -E 'package(fedimint-gateway-server) & test(gateway_client)'
    fi

    if [ -z "${FM_BITCOIND_GW_TEST_ONLY:-}" ] || [ "${FM_BITCOIND_GW_TEST_ONLY:-}" = "not-gateway-client" ]; then
      cargo nextest run --locked --workspace --all-targets \
        ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
        ${TEST_ARGS_SERIALIZED} \
        -E 'package(fedimint-gateway-server) & not test(gateway_client)'
    fi

    >&2 echo "### Testing against bitcoind for ln-gateway - complete"
  fi

  # Switch to esplora and run wallet tests
  export FM_TEST_BACKEND_BITCOIN_RPC_KIND="esplora"
  export FM_TEST_BACKEND_BITCOIN_RPC_URL="http://127.0.0.1:$FM_PORT_ESPLORA"

  if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "esplora" ]; then
    >&2 echo "### Testing against esplora"
    cargo nextest run --locked --workspace --all-targets \
      ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
      ${TEST_ARGS_SERIALIZED} \
      -E 'package(fedimint-wallet-tests)'
    >&2 echo "### Testing against esplora - complete"
  fi

}
export -f run_tests

devimint external-daemons --exec bash -c 'run_tests'

echo "fm success: rust-tests"
