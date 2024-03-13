#!/usr/bin/env bash
# Runs a test to ensure an already spent input cannot be replayed

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

devimint cannot-replay-transaction
