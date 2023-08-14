#!/usr/bin/env bash
# Runs a simple load-test-tool test

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"
source ./scripts/build.sh

devimint load-test-tool-test
