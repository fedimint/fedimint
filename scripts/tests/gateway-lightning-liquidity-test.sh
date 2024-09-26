#!/usr/bin/env bash
# Runs a test to make sure the gateway liquidity API works as expected

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

gw_type=$1

gateway-tests lightning-liquidity-test --gw-type $gw_type
