#!/usr/bin/env bash


set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

# The federation size is the first script argument (default 7, the per-PR
# `test-ci-all` size; the daily check passes 19) rather than an env override,
# so an FM_FED_SIZE exported for a devimint environment cannot silently
# shrink the check. Remaining arguments are forwarded to devimint.
export FM_FED_SIZE="${1:-7}"
if [ $# -gt 0 ]; then shift; fi

>&2 echo "Testing ${FM_FED_SIZE} peer dkg (FM_ENABLE_IROH=${FM_ENABLE_IROH:-unset})"

env \
  RUST_LOG="${RUST_LOG:-info,jsonrpsee-client=off}" \
  FM_EXTRA_LONG_POLL=true \
  devimint "$@" dev-fed \
    --exec true
