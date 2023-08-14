#!/usr/bin/env bash

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"
source ./scripts/build.sh

devimint dev-fed &
eval "$(devimint env)"
devimint wait

echo Funding LND gateway e-cash wallet ...

wasm-pack test --firefox --headless fedimint-wasm-tests
