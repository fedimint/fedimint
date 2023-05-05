#!/usr/bin/env bash
# Runs a test to see what happens if a lightning node that is connected to a gateway dies

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"
source ./scripts/build.sh

devimint lightning-reconnect-test
