#!/usr/bin/env bash
# Runs a test to determine the latency of certain user actions

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path

devimint latency-tests "$@"
