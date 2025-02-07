#!/usr/bin/env bash

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"
export FM_ENABLE_MODULE_LNV2=${FM_ENABLE_MODULE_LNV2:-1}

source scripts/_common.sh
build_workspace
add_target_dir_to_path

if [ $# -eq 1 ]; then
    test=$1
    gateway-tests $test
elif [ $# -eq 2 ]; then
    test=$1
    gw_type=$2
    gateway-tests $test --gw-type $gw_type
else
    echo "Usage: $0 <test> <lnd|cln|ldk>"
    exit 1
fi
