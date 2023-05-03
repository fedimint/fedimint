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
cargo build ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --all --all-targets
# Avoid re-building tests in parallel in all test derivations
>&2 echo "Pre-building tests..."
cargo test --no-run ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -p fedimint-tests

function cli_test_reconnect() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "## START: ${FUNCNAME[0]}"
  unshare -rn bash -c "ip link set lo up && exec unshare --user ./scripts/reconnect-test.sh" 2>&1 | ts -s
  echo "## COMPLETE: ${FUNCNAME[0]}"
}
export -f cli_test_reconnect

function cli_test_lightning_reconnect() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "## START: ${FUNCNAME[0]}"
  unshare -rn bash -c "ip link set lo up && exec unshare --user ./scripts/lightning-reconnect-test.sh" 2>&1 | ts -s
  echo "## COMPLETE: ${FUNCNAME[0]}"
}
export -f cli_test_lightning_reconnect

function cli_test_latency() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "## START: ${FUNCNAME[0]}"
  unshare -rn bash -c "ip link set lo up && exec unshare --user ./scripts/latency-test.sh" 2>&1 | ts -s
  echo "## COMPLETE: ${FUNCNAME[0]}"
}
export -f cli_test_latency

function cli_test_cli() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "## START: ${FUNCNAME[0]}"
  unshare -rn bash -c "ip link set lo up && exec unshare --user ./scripts/cli-test.sh" 2>&1 | ts -s
  echo "## COMPLETE: ${FUNCNAME[0]}"
}
export -f cli_test_cli

function cli_test_rust_tests_bitcoind() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "## START: ${FUNCNAME[0]}"
  unshare -rn bash -c "ip link set lo up && exec unshare --user env FM_TEST_ONLY=bitcoind ./scripts/rust-tests.sh" 2>&1 | ts -s
  echo "## COMPLETE: ${FUNCNAME[0]}"
}
export -f cli_test_rust_tests_bitcoind

function cli_test_rust_tests_electrs() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "## START: ${FUNCNAME[0]}"
  unshare -rn bash -c "ip link set lo up && exec unshare --user env FM_TEST_ONLY=electrs ./scripts/rust-tests.sh" 2>&1 | ts -s
  echo "## COMPLETE: ${FUNCNAME[0]}"
}
export -f cli_test_rust_tests_electrs

function cli_test_rust_tests_esplora() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "## START: ${FUNCNAME[0]}"
  unshare -rn bash -c "ip link set lo up && exec unshare --user env FM_TEST_ONLY=esplora ./scripts/rust-tests.sh" 2>&1 | ts -s
  echo "## COMPLETE: ${FUNCNAME[0]}"
}
export -f cli_test_rust_tests_esplora

function cli_test_always_success() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "## START: ${FUNCNAME[0]}"
  # this must fail, so we know nix build is actually running tests
  unshare -rn bash -c "ip link set lo up && exec unshare --user ./scripts/always-success-test.sh" 2>&1 | ts -s
  echo "## COMPLETE: ${FUNCNAME[0]}"
}
export -f cli_test_always_success

tmpdir=$(mktemp --tmpdir -d XXXXX)
trap 'rm -r $tmpdir' EXIT
joblog="$tmpdir/joblog"

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
  --jobs '+0' \
  --memfree 1G \
  --nice 15 ::: \
  cli_test_always_success \
  cli_test_rust_tests_bitcoind \
  cli_test_rust_tests_electrs \
  cli_test_rust_tests_esplora \
  cli_test_latency \
  cli_test_reconnect \
  cli_test_lightning_reconnect \
  cli_test_cli ; then
  >&2 echo "All tests successful"
else
  >&2 echo "Some tests failed. Full job log:"
  cat "$joblog"
  >&2 echo "Search for '## FAILED' to find the end of the failing test"
  exit 1
fi

