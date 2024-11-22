#!/usr/bin/env bash

set -euo pipefail

job_name="$1"
shift 1

if [ -z "$job_name" ]; then
    >&2 "error: no job name"
    exit 1
fi

export FS_DIR_CACHE_LOCK_TIMEOUT_SECS="$((60 * 30))" # unlock after timeout in case our job fails misereably

USER_ROOT="$HOME"
if [ -n "${RUNNER_ROOT:-}" ]; then
    # In self-hosted nixos module runner, the HOME is actually /run/... which is memory-quota-limited
    # so use the persisted root dir instead
    USER_ROOT="$RUNNER_ROOT"
    # In our self-hosted runners the cache dir is actually local to instance and not shared,
    # so there is not point in locking it. And if the run gets killed due to concurrency groups
    # the lock might not get cleaned, and next job might need to wait for it to expire.
    # We should really be using some kind of sockets that would disappear automatically, but
    # for now making the timeout tiny is the easiest workaround.
    FS_DIR_CACHE_LOCK_TIMEOUT_SECS=1
fi
export FS_DIR_CACHE_ROOT="$USER_ROOT/.cache/fs-dir-cache" # directory to hold all cache (sub)directories
export FS_DIR_CACHE_LOCK_ID="pid-$$-rnd-$RANDOM"     # acquire lock based on the current pid and something random (just in case pid gets reused)
export FS_DIR_CACHE_KEY_NAME="$job_name"             # the base name of our key

log_file="$FS_DIR_CACHE_ROOT/log"

fs-dir-cache gc unused --seconds "$((5 * 24 * 60 * 60))" # delete caches not used in more than a 5 days

export log_file
export job_name
src_dir=$(pwd)
export src_dir

function run_in_cache() {
    echo "$(date --rfc-3339=seconds) RUN job=$job_name dir=$(pwd)" >> "$log_file"
    >&2 echo "$(date --rfc-3339=seconds) RUN job=$job_name dir=$(pwd)"
    CARGO_BUILD_TARGET_DIR="$(pwd)"
    export CARGO_BUILD_TARGET_DIR
    cd "$src_dir"

    function on_exit() {
        local exit_code=$?

        echo "$(date --rfc-3339=seconds) END job=$job_name code=$exit_code" >> "$log_file"
        >&2 echo "$(date --rfc-3339=seconds) END job=$job_name code=$exit_code"

        exit $exit_code
    }
    trap on_exit EXIT

    "$@"
}
export -f run_in_cache


fs-dir-cache exec \
    --key-file Cargo.lock --key-str "${CARGO_PROFILE-:dev}" --key-file flake.lock \
    -- \
    bash -c 'run_in_cache "$@"' _ "$@"
