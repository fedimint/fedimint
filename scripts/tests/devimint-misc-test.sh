#!/usr/bin/env bash
# Place for any misc (ad-hoc) tests that require devimint env

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

# verify that client can do an offline operation without networking
devimint dev-fed --exec bash -c 'unshare --net --user fedimint-cli --data-dir "$FM_CLIENT_DIR" info'
