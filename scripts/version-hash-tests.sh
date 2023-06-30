#!/usr/bin/env bash
# Runs a test to verify that all fedimint binaries were built from the current git HEAD hash

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"
source ./scripts/build.sh

devimint version-hash-tests
