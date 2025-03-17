#!/usr/bin/env bash

set -euo pipefail

source scripts/_common.sh

ensure_in_dev_shell
build_workspace
add_target_dir_to_path

# In our dev env we want to use the current aliases from the source code
export FM_DEVIMINT_STATIC_DATA_DIR="${REPO_ROOT}/devimint/share"

devimint --link-test-dir "${CARGO_BUILD_TARGET_DIR:-$PWD/target}/devimint" "$@" dev-fed --exec bash -c 'mprocs -c misc/mprocs.yaml 2>$FM_LOGS_DIR/devimint-outer.log'
