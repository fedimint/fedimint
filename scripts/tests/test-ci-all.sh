#!/usr/bin/env bash

set -euo pipefail

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

function reconnect_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/reconnect-test.sh
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

function latency_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/latency-test.sh
}
export -f latency_test

function devimint_cli_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/devimint-cli-test.sh
}
export -f devimint_cli_test

function load_test_tool_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/load-test-tool-test.sh
}
export -f load_test_tool_test

function backend_test_bitcoind() {
  fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=bitcoind ./scripts/tests/backend-test.sh
}
export -f backend_test_bitcoind

function backend_test_electrs() {
  fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=electrs ./scripts/tests/backend-test.sh
}
export -f backend_test_electrs

function backend_test_esplora() {
  fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=esplora ./scripts/tests/backend-test.sh
}
export -f backend_test_esplora

function wasm_test() {
  fm-run-test "${FUNCNAME[0]}" env FM_TEST_ONLY=esplora ./scripts/tests/wasm-test.sh
}
export -f wasm_test

function always_success_test() {
  fm-run-test "${FUNCNAME[0]}" ./scripts/tests/always-success-test.sh
}
export -f always_success_test

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
# NOTE: try to keep the slowest tests first, except 'always_success_test',
# as it's used for failure test
if parallel \
  --halt-on-error 1 \
  --joblog "$joblog" \
  --timeout 600 \
  --load 150% \
  --delay 5 \
  --jobs "$parallel_jobs" \
  --memfree 1G \
  --nice 15 ::: \
  always_success_test \
  backend_test_bitcoind \
  backend_test_electrs \
  backend_test_esplora \
  latency_test \
  reconnect_test \
  lightning_reconnect_test \
  gateway_reboot_test \
  devimint_cli_test \
  load_test_tool_test ; then
  >&2 echo "All tests successful"
else
  >&2 echo "Some tests failed. Full job log:"
  cat "$joblog"
  >&2 echo "Search for '## FAILED' to find the end of the failing test"
  exit 1
fi
