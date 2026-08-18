#!/usr/bin/env bash
# Runs the 1p1c package submission test against a real bitcoind.
#
# The test submits a zero-fee parent together with a fee-paying child and
# asserts the package is accepted where the parent alone is rejected. This is
# the property walletv2's pinning fix depends on (see PINNING.md). The mock
# bitcoin backend has no mempool policy, so this only works against a real node.
#
# Any extra arguments are forwarded to `cargo nextest run`.

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
ensure_in_dev_shell
build_workspace
add_target_dir_to_path
make_fm_test_marker

EXTRA_ARGS=("$@")
export EXTRA_ARGS_STR="${EXTRA_ARGS[*]:-}"

function run_test() {
  set -euo pipefail

  export FM_TEST_USE_REAL_DAEMONS=1
  export RUST_BACKTRACE=1
  export RUST_LIB_BACKTRACE=0

  >&2 echo "### Running package submission test"

  # shellcheck disable=SC2086
  cargo nextest run --locked --workspace --all-targets \
    ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
    --test-threads=1 ${EXTRA_ARGS_STR} \
    -E 'package(fedimint-server-bitcoin-rpc)'
}
export -f run_test

devimint external-daemons --exec bash -c 'run_test'

echo "fm success: package-submission-test"
