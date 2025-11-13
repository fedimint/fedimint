#!/usr/bin/env bash


set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

export FM_FED_SIZE=7

>&2 echo "Testing ${FM_FED_SIZE} peer dkg"

env
  RUST_LOG="${RUST_LOG:-info,jsonrpsee-client=off}" \
  FM_EXTRA_LONG_POLL=true \
  devimint "$@" dev-fed \
    --exec true
