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
cargo build ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --all --all-targets

function cli_test_reconnect() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "### Starting reconnect test..."
  unshare -rn bash -c "ip link set lo up && exec unshare --user ./scripts/reconnect-test.sh" 2>&1 | ts -s
}
export -f cli_test_reconnect

function cli_test_upgrade() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "### Starting upgrade test..."
  unshare -rn bash -c "ip link set lo up && exec unshare --user ./scripts/upgrade-test.sh" 2>&1 | ts -s
}
export -f cli_test_upgrade

function cli_test_latency() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "### Starting latency test..."
  unshare -rn bash -c "ip link set lo up && exec unshare --user ./scripts/latency-test.sh" 2>&1 | ts -s
}
export -f cli_test_latency

function cli_test_cli() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "### Starting cli test..."
  unshare -rn bash -c "ip link set lo up && exec unshare --user ./scripts/cli-test.sh" 2>&1 | ts -s
}
export -f cli_test_cli

function cli_test_rust_tests() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "### Starting integration test..."
  unshare -rn bash -c "ip link set lo up && exec unshare --user ./scripts/rust-tests.sh" 2>&1 | ts -s
}
export -f cli_test_rust_tests

function cli_test_always_fail() {
  set -eo pipefail # pipefail must be set manually again
  trap 'echo "## FAILED: ${FUNCNAME[0]}"' ERR 

  echo "### Starting always_fail test..."
  # this must fail, so we know nix build is actually running tests
  ! unshare -rn bash -c "ip link set lo up && exec unshare --user ./scripts/always-fail-test.sh" 2>&1 | ts -s
}
export -f cli_test_always_fail

tmpdir=$(mktemp --tmpdir -d XXXXX)
trap 'rm -r $tmpdir' EXIT
joblog="$tmpdir/joblog"

>&2 echo "### Starting all tests in parallel..."
# --load to keep the load under-control, especially during target dir extraction
# --delay to let nix start extracting and bump the load
# --memfree to make sure tests have enough memory to run
# --nice to let you browse twitter without lag while the tests are running
# NOTE: try to keep the slowest tests first
if parallel \
  --halt-on-error 1 \
  --joblog "$joblog" \
  --timeout 600 \
  --load 150% \
  --delay 5 \
  --memfree 512M \
  --nice 15 ::: \
  cli_test_rust_tests \
  cli_test_latency \
  cli_test_reconnect \
  cli_test_upgrade \
  cli_test_cli \
  cli_test_always_fail ; then
  >&2 echo "All tests successful"
else
  >&2 echo "Some tests failed. Full job log:"
  cat "$joblog"
  >&2 echo "Search for '## FAILED' to find the end of the failing test"
fi

