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
cargo test --no-run ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --workspace

function cli_test_reconnect() {
  fm-run-isolated-test "${FUNCNAME[0]}" ./scripts/tests/reconnect-test.sh
}
export -f cli_test_reconnect

function cli_test_lightning_reconnect() {
  fm-run-isolated-test "${FUNCNAME[0]}" ./scripts/tests/lightning-reconnect-test.sh
}
export -f cli_test_lightning_reconnect

function cli_test_latency() {
  fm-run-isolated-test "${FUNCNAME[0]}" ./scripts/tests/latency-test.sh
}
export -f cli_test_latency

function cli_test_cli() {
  fm-run-isolated-test "${FUNCNAME[0]}" ./scripts/tests/cli-test.sh
}
export -f cli_test_cli

function cli_load_test_tool_test() {
  fm-run-isolated-test "${FUNCNAME[0]}" ./scripts/tests/load-test-tool-test.sh
}
export -f cli_load_test_tool_test

function cli_test_rust_tests_bitcoind() {
  fm-run-isolated-test "${FUNCNAME[0]}" env FM_TEST_ONLY=bitcoind ./scripts/tests/rust-tests.sh
}
export -f cli_test_rust_tests_bitcoind

function cli_test_rust_tests_electrs() {
  fm-run-isolated-test "${FUNCNAME[0]}" env FM_TEST_ONLY=electrs ./scripts/tests/rust-tests.sh
}
export -f cli_test_rust_tests_electrs

function cli_test_rust_tests_esplora() {
  fm-run-isolated-test "${FUNCNAME[0]}" env FM_TEST_ONLY=esplora ./scripts/tests/rust-tests.sh
}
export -f cli_test_rust_tests_esplora

function cli_test_wasm() {
  fm-run-isolated-test "${FUNCNAME[0]}" env FM_TEST_ONLY=esplora ./scripts/tests/wasm-tests.sh
}
export -f cli_test_wasm

function cli_test_always_success() {
  fm-run-isolated-test "${FUNCNAME[0]}" ./scripts/tests/always-success-test.sh
}
export -f cli_test_always_success

export parallel_jobs='+0'

if [ "$(uname -s)" == "Darwin" ]; then
  # We rely on `unshare` to run all tests in separate network namespaces
  # This is not possible on MacOS, so we run every test serially with a no-op fake 'unshare'
  parallel_jobs='1'
fi

tmpdir=$(mktemp --tmpdir -d XXXXX)
trap 'rm -r $tmpdir' EXIT
joblog="$tmpdir/joblog"

PATH="$(pwd)/scripts/dev/run-isolated-test/:$PATH"

>&2 echo "## Starting all tests in parallel..."
# --load to keep the load under-control, especially during target dir extraction
# --delay to let nix start extracting and bump the load
# --memfree to make sure tests have enough memory to run
# --nice to let you browse twitter without lag while the tests are running
# NOTE: try to keep the slowest tests first, except 'cli_test_always_success',
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
  cli_test_always_success \
  cli_test_rust_tests_bitcoind \
  cli_test_rust_tests_electrs \
  cli_test_rust_tests_esplora \
  cli_test_latency \
  cli_test_reconnect \
  cli_test_lightning_reconnect \
  cli_test_cli \
  cli_load_test_tool_test ; then
  >&2 echo "All tests successful"
else
  >&2 echo "Some tests failed. Full job log:"
  cat "$joblog"
  >&2 echo "Search for '## FAILED' to find the end of the failing test"
  exit 1
fi
