#!/usr/bin/env bash

set -euo pipefail

source scripts/_common.sh

# prevent locale settings messing with some setups
export LANG=C

if [ "$(ulimit -Sn)" -lt "10000" ]; then
  >&2 echo "⚠️  ulimit too small. Running 'ulimit -Sn 10000' to avoid problems running tests"
  ulimit -Sn 10000
fi

# https://stackoverflow.com/a/72183258/134409
# this hangs in CI (no tty?)
# yes 'will cite' | parallel --citation 2>/dev/null 1>/dev/null || true
if [ -n "${HOME:-}" ] && [ -d "$HOME" ]; then
  mkdir -p "$HOME/.parallel"
  touch "$HOME/.parallel/will-cite"
fi

# Avoid re-building workspace in parallel in all test derivations
# Note: Respect 'CARGO_PROFILE' that crane uses
>&2 echo "Pre-building workspace..."
runLowPrio cargo build ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --workspace --all-targets
# Avoid re-building tests in parallel in all test derivations
>&2 echo "Pre-building tests..."
runLowPrio cargo nextest run --no-run ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --workspace --all-targets

# We've just built everything there is to built, so we should not have a
# need to be build things again from now on, but since cargo does not
# let us enforce it, we need to go behind its back. We put a fake 'rustc'
# in the PATH.
# If you really need to break this rule, ping dpc
export CARGO_DENY_COMPILATION=1

function rust_unit_tests() {
  # unit tests don't use binaries from old versions, so there's no need to run for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" cargo nextest run ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --workspace --all-targets
  fi
}
export -f rust_unit_tests

function recoverytool_tests() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/recoverytool-tests.sh
}
export -f recoverytool_tests

function reconnect_test() {
  # reconnect-test runs a degraded federation, so we need to override FM_OFFLINE_NODES
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/reconnect-test.sh
}
export -f reconnect_test

function lightning_reconnect_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/lightning-reconnect-test.sh
}
export -f lightning_reconnect_test

function gateway_reboot_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/gateway-reboot-test.sh
}
export -f gateway_reboot_test

function gateway_config_test_lnd() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/gateway-module-test.sh config-test lnd
}
export -f gateway_config_test_lnd

function gateway_config_test_cln() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/gateway-module-test.sh config-test cln
}
export -f gateway_config_test_cln

function gateway_restore_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/gateway-module-test.sh backup-restore-test
}
export -f gateway_restore_test

function gateway_liquidity_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/gateway-module-test.sh liquidity-test
}
export -f gateway_liquidity_test

function latency_test_reissue() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/latency-test.sh reissue
}
export -f latency_test_reissue

function latency_test_ln_send() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/latency-test.sh ln-send
}
export -f latency_test_ln_send

function latency_test_ln_receive() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/latency-test.sh ln-receive
}
export -f latency_test_ln_receive

function latency_test_fm_pay() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/latency-test.sh fm-pay
}
export -f latency_test_fm_pay

function latency_test_restore() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/latency-test.sh restore
}
export -f latency_test_restore

function meta_module() {
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/meta-module-test.sh
}
export -f meta_module

function lnv2_module() {
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/lnv2-module-test.sh
}
export -f lnv2_module

function mint_client_sanity() {
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/mint-client-sanity.sh
}
export -f mint_client_sanity

function mint_client_restore() {
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/mint-client-restore.sh
}
export -f mint_client_restore

function guardian_backup() {
  # guardian-backup-test runs a degraded federation, so we need to override FM_OFFLINE_NODES
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/guardian-backup.sh
}
export -f guardian_backup

function cannot_replay_tx() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/cannot-replay-tx.sh
}
export -f cannot_replay_tx

function circular_deposit() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/circular-deposit-test.sh
}
export -f circular_deposit

function wallet_recovery() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/wallet-recovery-test.sh
}
export -f wallet_recovery

function devimint_cli_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/devimint-cli-test.sh
}
export -f devimint_cli_test

function devimint_cli_test_single() {
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/devimint-cli-test-single.sh
}
export -f devimint_cli_test_single

function load_test_tool_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/load-test-tool-test.sh
}
export -f load_test_tool_test

function bckn_bitcoind_dummy() {
  # backend tests don't support different versions, so we skip for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=bitcoind FM_BITCOIND_TEST_ONLY=dummy ./scripts/tests/backend-test.sh
  fi
}
export -f bckn_bitcoind_dummy

function bckn_bitcoind_mint() {
  # backend tests don't support different versions, so we skip for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=bitcoind FM_BITCOIND_TEST_ONLY=mint ./scripts/tests/backend-test.sh
  fi
}
export -f bckn_bitcoind_mint

function bckn_bitcoind_wallet() {
  # backend tests don't support different versions, so we skip for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=bitcoind FM_BITCOIND_TEST_ONLY=wallet ./scripts/tests/backend-test.sh
  fi
}
export -f bckn_bitcoind_wallet

function bckn_bitcoind_ln() {
  # backend tests don't support different versions, so we skip for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=bitcoind FM_BITCOIND_TEST_ONLY=ln ./scripts/tests/backend-test.sh
  fi
}
export -f bckn_bitcoind_ln

function bckn_bitcoind_lnv2() {
  # backend tests don't support different versions, so we skip for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=bitcoind FM_BITCOIND_TEST_ONLY=lnv2 ./scripts/tests/backend-test.sh
  fi
}
export -f bckn_bitcoind_lnv2

function bckn_gw_client() {
  # backend tests don't support different versions, so we skip for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=bitcoind-ln-gateway FM_BITCOIND_GW_TEST_ONLY=gateway-client ./scripts/tests/backend-test.sh
  fi
}
export -f bckn_gw_client

function bckn_gw_not_client() {
  # backend tests don't support different versions, so we skip for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=bitcoind-ln-gateway FM_BITCOIND_GW_TEST_ONLY=not-gateway-client ./scripts/tests/backend-test.sh
  fi
}
export -f bckn_gw_not_client

function bckn_electrs() {
  # backend tests don't support different versions, so we skip for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=electrs ./scripts/tests/backend-test.sh
  fi
}
export -f bckn_electrs

function bckn_esplora() {
  # backend tests don't support different versions, so we skip for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=esplora ./scripts/tests/backend-test.sh
  fi
}
export -f bckn_esplora

function wasm_test() {
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    # TODO: move this check to when forming the test list
    if which wasm-pack 1>/dev/null 2>/dev/null ; then
      fm-run-test "${FUNCNAME[0]}" ./scripts/tests/wasm-test.sh
    else
      echo >&2 "### SKIP: ${FUNCNAME[0]}"
    fi
  fi
}
export -f wasm_test

function always_success_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/always-success-test.sh
}
export -f always_success_test

tagged_versions=("$@")
num_versions="$#"
versions=( "${tagged_versions[@]}" "current" )
if [[ "$num_versions" == "0" ]]; then
  mapfile -t version_matrix < <(generate_current_only_matrix "${versions[@]}")
else
  # precompile binaries
  binaries=( "fedimintd" "fedimint-cli" "gateway-cli" "gatewayd" "gateway-cln-extension" )
  for version in "${versions[@]}" ; do
    if [ "$version" == "current" ] ; then
      continue
    fi
    for binary in "${binaries[@]}" ; do
      var_name=$(nix_binary_version_var_name "$binary" "$version")
      export "${var_name}=$(nix_build_binary_for_version "$binary" "$version")"
    done
  done

  if [ -n "${FM_FULL_VERSION_MATRIX:-}" ]; then
    mapfile -t version_matrix < <(generate_full_matrix "${versions[@]}")
  else
    mapfile -t version_matrix < <(generate_partial_matrix "${versions[@]}")
  fi
fi

tests_to_run_in_parallel=()
for _ in $(seq "${FM_TEST_CI_ALL_TIMES:-1}"); do
# NOTE: try to keep the slowest tests first, except 'always_success_test',
# as it's used for failure test
tests_to_run_in_parallel+=(
  "always_success_test"
  # "rust_unit_tests"
  # TODO: unfortunately it seems like something about headless firefox is broken when
  # running in xarg -P or gnu parallel. Try re-enabling in the future and see if it works.
  # Other than this problem, everything about it is working.
  # "wasm_test"
  # "bckn_bitcoind_dummy"
  # "bckn_bitcoind_mint"
  # "bckn_bitcoind_wallet"
  # "bckn_bitcoind_ln"
  # "bckn_bitcoind_lnv2"
  # "bckn_gw_client"
  # "bckn_gw_not_client"
  # TODO: https://github.com/fedimint/fedimint/issues/5917
  # disabling while we investigate 60s timeouts causing CI flakiness
  # "bckn_electrs"
  # "bckn_esplora"
  # "latency_test_reissue"
  # "latency_test_ln_send"
  # "latency_test_ln_receive"
  # "latency_test_fm_pay"
  # "latency_test_restore"
  # "reconnect_test"
  # "lightning_reconnect_test"
  "gateway_reboot_test"
  # "gateway_config_test_cln"
  # "gateway_config_test_lnd"
  # "gateway_restore_test"
  # "gateway_liquidity_test"
  # "lnv2_module"
  # "devimint_cli_test"
  # "devimint_cli_test_single"
  # "load_test_tool_test"
  # "recoverytool_tests"
  # "guardian_backup"
  # "meta_module"
  # "mint_client_sanity"
  # "mint_client_restore"
  # "cannot_replay_tx"
  # "circular_deposit"
  # "wallet_recovery"
)
done

tests_with_versions=()
for version_combo in "${version_matrix[@]}"; do
  for test in "${tests_to_run_in_parallel[@]}"; do
    tests_with_versions+=("run_test_for_versions $test $version_combo")
  done
done

parsed_test_commands=$(printf "%s\n" "${tests_with_versions[@]}")

parallel_args=()

if [ -z "${CI:-}" ] && [[ -t 1 ]] && [ -z "${FM_TEST_CI_ALL_DISABLE_ETA:-}" ]; then
  parallel_args+=(--eta)
fi

if [ -n "${FM_TEST_CI_ALL_JOBS:-}" ]; then
  # when specifically set, use the env var
  parallel_args+=(--jobs "${FM_TEST_CI_ALL_JOBS}")
elif [ -n "${CI:-}" ] || [ "${CARGO_PROFILE:-}" == "ci" ]; then
  parallel_args+=(--jobs $(($(nproc) / 2 + 1)))
else
  # on dev computers default to `num_cpus / 2 + 1` max parallel jobs
  parallel_args+=(--jobs "${FM_TEST_CI_ALL_JOBS:-$(($(nproc) / 2 + 1))}")
fi

parallel_args+=(--timeout "${FM_TEST_CI_ALL_TIMEOUT:-300}")

parallel_args+=(--load "${FM_TEST_CI_ALL_MAX_LOAD:-$(($(nproc) / 3 + 1))}")
# --delay to let nix start extracting and bump the load
# usually not needed, as '--jobs' will keep a cap on the load anyway
parallel_args+=(--delay "${FM_TEST_CI_ALL_DELAY:-0}")

tmpdir=$(mktemp --tmpdir -d XXXXX)
trap 'rm -r $tmpdir' EXIT
joblog="$tmpdir/joblog"

PATH="$(pwd)/scripts/dev/run-test/:$PATH"

parallel_args+=(
  --joblog "$joblog"
  --noswap
  --memfree 2G
)

>&2 echo "## Starting all tests in parallel..."
>&2 echo "parallel ${parallel_args[*]}"

# --memfree to make sure tests have enough memory to run
# --nice to let you browse twitter without lag while the tests are running
echo "$parsed_test_commands" | shuf | if parallel \
  "${parallel_args[@]}" ; then
  >&2 echo "All tests successful"
else
  >&2 echo "Some tests failed:"
  awk '{ if($7 != "0") print $0 "\n" }' < "$joblog"
  >&2 echo "Search for '## FAIL' to find the end of the failing test"
  exit 1
fi
