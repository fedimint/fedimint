#!/usr/bin/env bash

set -euo pipefail

export RUST_LOG="${RUST_LOG:-info}"

source ./scripts/lib.sh
source ./scripts/build.sh

devimint wasm-test-setup &
auto_kill_last_cmd

eval "$(devimint env)"
devimint wait

echo Funding LND gateway e-cash wallet ...

wasm-pack test --firefox --headless fedimint-wasm-tests
