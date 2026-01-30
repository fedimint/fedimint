#!/usr/bin/env bash
# Runs guardian metadata integration test

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

devimint guardian-metadata-tests
