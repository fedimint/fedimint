#!/usr/bin/env bash
# Runs a test to see what happens if a lightning node that is connected to a gateway dies

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

devimint lightning-reconnect-test
