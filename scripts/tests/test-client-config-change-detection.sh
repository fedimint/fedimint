#!/usr/bin/env bash
# Tests that client can detect federation config changes when servers restart with new module configurations

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

devimint test-client-config-change-detection