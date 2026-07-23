#!/usr/bin/env bash

set -euo pipefail

export RUST_LOG="${RUST_LOG:-info}"

# This federation is configured with the WebSocket API only.
export FM_IROH_NEXT_ENABLE=false

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

# fedimintd now enables the v2 module set by default, but this test drives
# the v1 client modules (e.g. `ln` list-gateways). Unlike the main suite,
# the wasm test runs as its own derivation and does not flow through
# `run_test_for_versions`, so pin the v1 module set explicitly here. LNv2
# stays enabled by default, matching the previous wasm-test federation.
export FM_ENABLE_MODULE_LNV1=1
export FM_ENABLE_MODULE_MINT=1
export FM_ENABLE_MODULE_MINTV2=0
export FM_ENABLE_MODULE_WALLET=1
export FM_ENABLE_MODULE_WALLETV2=0


function run_tests() {
  set -euo pipefail

  echo Funding LND gateway e-cash wallet ...

  # Since this is going to effectively `cargo build -p ...` it needs to go
  # to it's own directory. Otherwise it would invalidate existing ./target.
  export CARGO_BUILD_TARGET_DIR
  CARGO_BUILD_TARGET_DIR="${CARGO_BUILD_TARGET_DIR:-${PWD}/target}"
  CARGO_BUILD_TARGET_DIR="${CARGO_BUILD_TARGET_DIR}/pkgs/fedimint-wasm-tests"
  WASM_BINDGEN_TEST_TIMEOUT=300 wasm-pack test --firefox --headless fedimint-wasm-tests ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -- --nocapture
}
export -f run_tests

devimint wasm-test-setup --exec bash -c run_tests
