#!/usr/bin/env bash

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path

# Check if both arguments are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <test> <lnd|cln|ldk>"
    exit 1
fi

test=$1
gw_type=$2

gateway-tests $test --gw-type $gw_type
