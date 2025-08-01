#!/usr/bin/env bash
# Tests that client info commands work even when all federation servers are offline

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

devimint test-offline-client-initialization