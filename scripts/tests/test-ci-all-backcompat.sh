#!/usr/bin/env bash

# previous versions did not have unknown module so can't support it,
# disable devimint enabling it in Federations
export FM_USE_UNKNOWN_MODULE=0

path="$CARGO_BUILD_TARGET_DIR/ci/deps/libserde_json-09c44f0222198895.rmeta"
ls -alh "$path"
md5sum "$path"

./scripts/tests/test-ci-all.sh "$@"
