#!/usr/bin/env bash
# Runs a test to see what happens if a server dies and rejoins

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"
source ./scripts/build.sh

fedimint-bin-tests reconnect-test
