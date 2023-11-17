#!/usr/bin/env bash

set -euo pipefail

export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker


function run_tests() {
  set -euo pipefail

  echo Funding LND gateway e-cash wallet ...

  WASM_BINDGEN_TEST_TIMEOUT=120 wasm-pack test --firefox --headless fedimint-wasm-tests
}
export -f run_tests

devimint wasm-test-setup --exec bash -c run_tests
