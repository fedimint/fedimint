#!/usr/bin/env bash

# previous versions did not have unknown module so can't support it,
# disable devimint enabling it in Federations
export FM_USE_UNKNOWN_MODULE=0
./scripts/tests/test-ci-all.sh "$@"
