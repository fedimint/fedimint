#!/usr/bin/env bash
# Runs a test to ensure a wallet restored from its seed claims a payment made
# to one of its reserved addresses.

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path

fedimint-walletv2-devimint-tests recovery
