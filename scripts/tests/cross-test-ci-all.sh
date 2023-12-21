#!/usr/bin/env bash

set -euo pipefail
set -x

# Test current versions against gatewayd v0.2
export FM_GATEWAYD_BASE_EXECUTABLE="nix run git+https://github.com/fedimint/fedimint.git?ref=releases/v0.2#gatewayd --"
# shellcheck disable=SC2260
$FM_GATEWAYD_BASE_EXECUTABLE --help || true
./scripts/tests/test-ci-all.sh