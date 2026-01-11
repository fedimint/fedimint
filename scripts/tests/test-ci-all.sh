#!/usr/bin/env bash

set -euo pipefail

source scripts/_common.sh

# prevent locale settings messing with some setups
export LANG=C

if [ "$(ulimit -Sn)" -lt "10000" ]; then
  >&2 echo "⚠️  ulimit too small. Running 'ulimit -Sn 10000' to avoid problems running tests"
  ulimit -Sn 10000
fi

>&2 echo "Iroh DHT & Iroh next-stack are disabled during tests"
export FM_IROH_ENABLE_DHT=false
export FM_IROH_ENABLE_NEXT=false
export FM_IROH_DHT_ENABLE=false
export FM_IROH_NEXT_ENABLE=false
export FM_IROH_RELAYS_ENABLE=false
export FM_IROH_N0_DISCOVERY_ENABLE=false
export FM_IROH_PKARR_RESOLVER_ENABLE=false
export FM_IROH_PKARR_PUBLISHER_ENABLE=false

export RUST_LOG="fm::test=debug,info,${RUST_LOG:-}"

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
build_workspace
# Avoid re-building tests in parallel in all test derivations
>&2 echo "Pre-building tests..."
build_workspace_tests

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

function ln_reconnect_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/lightning-reconnect-test.sh
}
export -f ln_reconnect_test

function gw_reboot_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/gateway-reboot-test.sh
}
export -f gw_reboot_test

function gw_config_test_lnd() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/gateway-module-test.sh config-test lnd
}
export -f gw_config_test_lnd

function gw_restore_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/gateway-module-test.sh backup-restore-test
}
export -f gw_restore_test

function gw_liquidity_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/gateway-module-test.sh liquidity-test
}
export -f gw_liquidity_test

function gw_esplora_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/gateway-module-test.sh esplora-test
}
export -f gw_esplora_test

function latency_reissue() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/latency-test.sh reissue
}
export -f latency_reissue

function latency_ln_send() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/latency-test.sh ln-send
}
export -f latency_ln_send

function latency_ln_receive() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/latency-test.sh ln-receive
}
export -f latency_ln_receive

function latency_fm_pay() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/latency-test.sh fm-pay
}
export -f latency_fm_pay

function latency_restore() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/latency-test.sh restore
}
export -f latency_restore

function meta_module() {
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/meta-module-test.sh
}
export -f meta_module

function lnv2_module_gateway_registration() {
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/lnv2-module-test.sh gateway-registration
}
export -f lnv2_module_gateway_registration

function lnv2_module_payments() {
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/lnv2-module-test.sh payments
}
export -f lnv2_module_payments

function lnv2_module_lnurl_pay() {
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/lnv2-module-test.sh lnurl-pay
}
export -f lnv2_module_lnurl_pay

function lnv1_lnv2_swap() {
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/lnv1-lnv2-swap-test.sh
}
export -f lnv1_lnv2_swap

function walletv2_module() {
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/walletv2-module-test.sh
}
export -f walletv2_module

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

function test_offline_client_initialization() {
  # test runs with all servers offline, so we need to override FM_OFFLINE_NODES
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/test-offline-client-initialization.sh
}
export -f test_offline_client_initialization

function test_client_config_change_detection() {
  # test modifies server configs and restarts, so we need to override FM_OFFLINE_NODES
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/test-client-config-change-detection.sh
}
export -f test_client_config_change_detection

function test_guardian_password_change() {
  # test modifies server configs and restarts, so we need to override FM_OFFLINE_NODES
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/test-guardian-password-change.sh
}
export -f test_guardian_password_change

function circular_deposit() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/circular-deposit-test.sh
}
export -f circular_deposit

function wallet_recovery() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/wallet-recovery-test.sh
}
export -f wallet_recovery

function wallet_recovery_2() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/wallet-recovery-test-2.sh
}
export -f wallet_recovery_2

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

function recurringd_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/recurringd-test.sh
}
export -f recurringd_test

function always_success_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/always-success-test.sh
}
export -f always_success_test

function large_setup_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/large-setup-test.sh
}
export -f large_setup_test

# allows versions to be passed in as either a single string or multiple params
# e.g. `"v0.3.0 v0.4.0"` is the same as `v0.3.0 v0.4.0`
if [ "$#" -eq 1 ]; then
  IFS=' ' read -r -a tagged_versions <<< "$1"
else
  tagged_versions=("$@")
fi
num_versions="$#"
versions=( "${tagged_versions[@]}" "current" )
if [[ "$num_versions" == "0" ]]; then
  mapfile -t version_matrix < <(generate_current_only_matrix "${versions[@]}")
else
  # precompile binaries
  binaries=( "fedimintd" "fedimint-cli" "gateway-cli" "gatewayd" )
  for version in "${versions[@]}" ; do
    if [ "$version" == "current" ] ; then
      continue
    fi
    for binary in "${binaries[@]}" ; do
      # for dkg we need to use the fedimint-cli version that matches fedimintd
      if [ "$binary" == "fedimintd" ]; then
        var_name=$(nix_binary_version_var_name "fedimint-cli" "$version")
        export "${var_name}=$(nix_build_binary_for_version "fedimint-cli" "$version")"
      fi
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
  "rust_unit_tests"
  # TODO: unfortunately it seems like something about headless firefox is broken when
  # running in xarg -P or gnu parallel. Try re-enabling in the future and see if it works.
  # Other than this problem, everything about it is working.
  # "wasm_test"
  "bckn_bitcoind_dummy"
  "bckn_bitcoind_mint"
  "bckn_bitcoind_wallet"
  "bckn_bitcoind_ln"
  "bckn_bitcoind_lnv2"
  "bckn_gw_client"
  "bckn_gw_not_client"
  "bckn_esplora"
  "latency_reissue"
  "latency_ln_send"
  "latency_ln_receive"
  "latency_fm_pay"
  "latency_restore"
  "reconnect_test"
  "ln_reconnect_test"
  "gw_reboot_test"
  "gw_config_test_lnd"
  "gw_restore_test"
  "gw_liquidity_test"
  "lnv2_module_gateway_registration"
  "lnv2_module_payments"
  "lnv2_module_lnurl_pay"
  "lnv1_lnv2_swap"
  "walletv2_module"
  "devimint_cli_test"
  "devimint_cli_test_single"
  "load_test_tool_test"
  "recoverytool_tests"
  "guardian_backup"
  "meta_module"
  "mint_client_sanity"
  "mint_client_restore"
  "cannot_replay_tx"
  "test_offline_client_initialization"
  "test_client_config_change_detection"
  "test_guardian_password_change"
  "circular_deposit"
  "wallet_recovery"
  "wallet_recovery_2"
  "recurringd_test"
  "large_setup_test"
)
done

tests_with_versions=()
for version_combo in "${version_matrix[@]}"; do

  # read the versions from the format "FM: $fed_version CLI: $client_version GW: $gateway_version"
  IFS=' ' read -r -a tokens <<< "$version_combo"
  fed_version="${tokens[1]}"
  client_version="${tokens[3]}"
  gateway_version="${tokens[5]}"

  if are_all_versions_current "$fed_version" "$client_version" "$gateway_version"; then
    lnv2_flags=("LNv2: 1")
  elif supports_lnv2 "$fed_version" "$client_version" "$gateway_version"; then
    lnv2_flags=("LNv2: 0" "LNv2: 1")
  else
    lnv2_flags=("LNv2: 0")
  fi

  for test in "${tests_to_run_in_parallel[@]}"; do
    for lnv2 in "${lnv2_flags[@]}"; do
      tests_with_versions+=("run_test_for_versions $test $version_combo $lnv2")
    done
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

parallel_args+=(--timeout "${FM_TEST_CI_ALL_TIMEOUT:-360}")

parallel_args+=(--load "${FM_TEST_CI_ALL_MAX_LOAD:-$(($(nproc)))}")

# --delay to let nix start extracting and bump the load
# usually not needed, as '--jobs' will keep a cap on the load anyway
parallel_args+=(--delay "${FM_TEST_CI_ALL_DELAY:-.5}")

tmpdir=$(mktemp --tmpdir -d XXXXX)
trap 'rm -r $tmpdir' EXIT
joblog="$tmpdir/joblog"

PATH="$(pwd)/scripts/dev/run-test/:$PATH"

parallel_args+=(
  --halt-on-error 1
  --joblog "$joblog"
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
