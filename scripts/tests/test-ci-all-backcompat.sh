#!/usr/bin/env bash

# previous versions did not have unknown module so can't support it,
# disable devimint enabling it in Federations
export FM_USE_UNKNOWN_MODULE=0

export RUST_LOG=${RUST_LOG:-h2=off,fm=debug,info}


# older versions don't handle overrides disabling heavier Iroh functionality,
# so they can't do Iroh
export FM_ENABLE_IROH=false

./scripts/tests/test-ci-all.sh "$@"
