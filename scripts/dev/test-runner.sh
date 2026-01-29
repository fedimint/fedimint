#!/usr/bin/env bash

set -euo pipefail

source scripts/_common.sh
ensure_in_dev_shell
build_workspace

exec $CARGO_BUILD_TARGET_BIN_DIR/test-runner "$@"
