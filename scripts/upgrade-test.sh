#!/usr/bin/env bash
# Runs a test to see what happens if we upgrade consensus

set -euxo pipefail
export RUST_LOG="${RUST_LOG:-info,timing=trace}"
source ./scripts/build.sh

$FM_BIN_DIR/fedimint-bin-tests upgrade-test
