#!/usr/bin/env bash

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path

# Enable MintV2 and disable MintV1 when running MintV2 tests
export FM_ENABLE_MODULE_MINTV2=true
export FM_ENABLE_MODULE_MINT=false

mintv2-module-tests "$@"
