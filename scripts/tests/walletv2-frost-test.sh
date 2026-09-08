#!/usr/bin/env bash
# Runs the walletv2 FROST devimint test. Pass `--fed-sizes <N,...>` to set the
# federation sizes to test (e.g. `--fed-sizes 4,7,11`); each size is tested at
# every offline-guardian level from 0 up to its fault-tolerance threshold.

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path

env FM_EXTRA_LONG_POLL=true fedimint-walletv2-frost-test "$@"
