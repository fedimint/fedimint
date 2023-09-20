#!/usr/bin/env bash
# Runs a test to make sure gateways can reboot properly, with the expected state

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"
source ./scripts/build.sh

devimint gateway-reboot-test
