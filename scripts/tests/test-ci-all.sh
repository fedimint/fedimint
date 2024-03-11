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
cargo build ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --workspace --all-targets
# Avoid re-building tests in parallel in all test derivations
>&2 echo "Pre-building tests..."
cargo nextest run --no-run ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --workspace --all-targets

# We've just built everything there is to built, so we should not have a
# need to be build things again from now on, but since cargo does not
# let us enforce it, we need to go behind its back. We put a fake 'rustc'
# in the PATH.
# If you really need to break this rule, ping dpc
export FM_CARGO_DENY_COMPILATION=1

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

function guardian_backup() {
  # guardian-backup-test runs a degraded federation, so we need to override FM_OFFLINE_NODES
  fm-run-test "${FUNCNAME[0]}" env FM_OFFLINE_NODES=0 ./scripts/tests/guardian-backup.sh
}
export -f guardian_backup

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

function backend_test_bitcoind() {
  # backend tests don't support different versions, so we skip for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=bitcoind ./scripts/tests/backend-test.sh
  fi
}
export -f backend_test_bitcoind

function backend_test_bitcoind_ln_gateway() {
  # backend tests don't support different versions, so we skip for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=bitcoind-ln-gateway ./scripts/tests/backend-test.sh
  fi
}
export -f backend_test_bitcoind_ln_gateway

function backend_test_electrs() {
  # backend tests don't support different versions, so we skip for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=electrs ./scripts/tests/backend-test.sh
  fi
}
export -f backend_test_electrs

function backend_test_esplora() {
  # backend tests don't support different versions, so we skip for backwards-compatibility tests
  if [ -z "${FM_BACKWARDS_COMPATIBILITY_TEST:-}" ]; then
    fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=esplora ./scripts/tests/backend-test.sh
  fi
}
export -f backend_test_esplora

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
versions=( "current" "${tagged_versions[@]}" )
if [[ "$num_versions" == "0" ]]; then
  mapfile -t version_matrix < <(generate_current_only_matrix "${versions[@]}")
else
  # precompile binaries
  binaries=( "fedimintd" "fedimint-cli" "gateway-cli" "gatewayd" )
  parallel nix_build_binary_for_version "{1}" "{2}" ::: "${binaries[@]}" ::: "${tagged_versions[@]}"
  if [ -n "${FM_FULL_VERSION_MATRIX:-}" ]; then
    mapfile -t version_matrix < <(generate_full_matrix "${versions[@]}")
  else
    mapfile -t version_matrix < <(generate_partial_matrix "${versions[@]}")
  fi
fi

# NOTE: try to keep the slowest tests first, except 'always_success_test',
# as it's used for failure test
tests_to_run_in_parallel=(
  "always_success_test"
  "rust_unit_tests"
  # TODO: unfortunately it seems like something about headless firefox is broken when
  # running in xarg -P or gnu parallel. Try re-enabling in the future and see if it works.
  # Other than this problem, everything about it is working.
  # "wasm_test"
  "backend_test_bitcoind"
  "backend_test_bitcoind_ln_gateway"
  "backend_test_electrs"
  "backend_test_esplora"
  "latency_test_reissue"
  "latency_test_ln_send"
  "latency_test_ln_receive"
  "latency_test_fm_pay"
  "latency_test_restore"
  "reconnect_test"
  "lightning_reconnect_test"
  "gateway_reboot_test"
  "devimint_cli_test"
  "devimint_cli_test_single"
  "load_test_tool_test"
  "recoverytool_tests"
  "guardian_backup"
)

tests_with_versions=()
for test in "${tests_to_run_in_parallel[@]}"; do
  for version_combo in "${version_matrix[@]}"; do
    tests_with_versions+=("run_test_for_versions $test $version_combo")
  done
done

parsed_test_commands=$(printf "%s\n" "${tests_with_versions[@]}")

export parallel_jobs='+0'

tmpdir=$(mktemp --tmpdir -d XXXXX)
trap 'rm -r $tmpdir' EXIT
joblog="$tmpdir/joblog"

PATH="$(pwd)/scripts/dev/run-test/:$PATH"

>&2 echo "## Starting all tests in parallel..."
# --load to keep the load under-control, especially during target dir extraction
# --delay to let nix start extracting and bump the load
# --memfree to make sure tests have enough memory to run
# --nice to let you browse twitter without lag while the tests are running
echo "$parsed_test_commands" | if parallel \
  --halt-on-error 1 \
  --joblog "$joblog" \
  --timeout 600 \
  --load 1000% \
  --delay 5 \
  --jobs "$parallel_jobs" \
  --memfree 1G \
  --nice 15 ; then
  >&2 echo "All tests successful"
else
  >&2 echo "Some tests failed. Full job log:"
  cat "$joblog"
  >&2 echo "Search for '## FAIL' to find the end of the failing test"
  exit 1
fi
