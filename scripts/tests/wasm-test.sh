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

  # Since this is going to effectively `cargo build -p ...` it needs to go
  # to it's own directory. Otherwise it would invalidate existing ./target.
  export CARGO_BUILD_TARGET_DIR
  CARGO_BUILD_TARGET_DIR="${CARGO_BUILD_TARGET_DIR:-${PWD}/target}"
  CARGO_BUILD_TARGET_DIR="${CARGO_BUILD_TARGET_DIR}/pkgs/fedimint-wasm-tests"
  WASM_BINDGEN_TEST_TIMEOUT=300 wasm-pack test --firefox --headless fedimint-wasm-tests ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}}
}
export -f run_tests

devimint wasm-test-setup --exec bash -c run_tests
