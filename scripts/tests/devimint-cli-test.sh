#!/usr/bin/env bash
# Runs a CLI-based integration test

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"
source ./scripts/build.sh

devimint cli-tests
