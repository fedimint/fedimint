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

# 'cargo test' does not have a possibility of building whole workspace (to avoid any rebuilds), yet
# running just a subset of tests from a given package. To overcome it we parse the output of this
# command and run test binaries directly. Not elegant, but works.
available_tests="$(cargo test --no-run --workspace --all-targets 2>&1 | grep Executable | sed -n 's/.*(\([^)]*\)).*/\1/p')"

eval "$(devimint env)"
>&2 echo "### Setting up tests - complete"

$(echo $available_tests | tr ' ' '\n' | grep /fedimint_ln_server-) --test-threads=$(($(nproc) * 2)) "$@"

export FM_TEST_USE_REAL_DAEMONS=1

if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "bitcoind" ]; then
  >&2 echo "### Testing against bitcoind"
  $(echo $available_tests | tr ' ' '\n' | grep /ln_gateway-) --test-threads=$(($(nproc) * 2)) "$@"
  $(echo $available_tests | tr ' ' '\n' | grep /fedimint_ln_tests-) --test-threads=$(($(nproc) * 2)) "$@"
  $(echo $available_tests | tr ' ' '\n' | grep /fedimint_dummy_tests-) --test-threads=$(($(nproc) * 2)) "$@"
  $(echo $available_tests | tr ' ' '\n' | grep /fedimint_mint_tests-) --test-threads=$(($(nproc) * 2)) "$@"
  $(echo $available_tests | tr ' ' '\n' | grep /fedimint_wallet_tests-) --test-threads=$(($(nproc) * 2)) "$@"
  $(echo $available_tests | tr ' ' '\n' | grep /fedimint_tests-) --test-threads=$(($(nproc) * 2)) "$@"
  >&2 echo "### Testing against bitcoind - complete"
fi

# Switch to electrum and run wallet tests
export FM_BITCOIN_RPC_KIND="electrum"
export FM_BITCOIN_RPC_URL="tcp://127.0.0.1:50001"

if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "electrs" ]; then
  >&2 echo "### Testing against electrs"
  $(echo $available_tests | tr ' ' '\n' | grep /fedimint_wallet_tests-) --test-threads=$(($(nproc) * 2)) "$@"
  $(echo $available_tests | tr ' ' '\n' | grep /fedimint_tests-) wallet --test-threads=$(($(nproc) * 2)) "$@"
  >&2 echo "### Testing against electrs - complete"
fi

# Switch to esplora and run wallet tests
export FM_BITCOIN_RPC_KIND="esplora"
export FM_BITCOIN_RPC_URL="http://127.0.0.1:50002"
if [ -z "${FM_TEST_ONLY:-}" ] || [ "${FM_TEST_ONLY:-}" = "esplora" ]; then
  >&2 echo "### Testing against esplora"
  $(echo $available_tests | tr ' ' '\n' | grep /fedimint_wallet_tests-) --test-threads=$(($(nproc) * 2)) "$@"
  $(echo $available_tests | tr ' ' '\n' | grep /fedimint_tests-) wallet --test-threads=$(($(nproc) * 2)) "$@"
  >&2 echo "### Testing against esplora - complete"
fi

echo "fm success: rust-tests"
