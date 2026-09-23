#!/usr/bin/env bash

set -euo pipefail

# Experimental only: this exercises one bounded local run and does not prove
# safety or liveness for every connection ordering or scheduler interleaving.
# Existing production federations default to the Iroh guardian network stack.
# Pin it here so the experiment does not silently depend on devimint's
# legacy-network test default.
export FM_ENABLE_IROH=true
export FM_DUPLICATED_GUARDIAN_EXPERIMENT=1

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

devimint -n 4 reconnect-test
