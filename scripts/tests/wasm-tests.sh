#!/usr/bin/env bash

set -euo pipefail

export RUST_LOG="${RUST_LOG:-info}"

source ./scripts/lib.sh
source ./scripts/build.sh

devimint dev-fed &
pid=$!
kill_on_exit $pid dev-fed
PIDS+=( "$pid" )

eval "$(devimint env)"
devimint wait

echo Funding LND gateway e-cash wallet ...

wasm-pack test --firefox --headless fedimint-wasm-tests

kill "${PIDS[@]}"
wait "${PIDS[@]}"
