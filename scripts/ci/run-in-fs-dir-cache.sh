#!/usr/bin/env bash

set -euo pipefail

job_name="$1"
shift 1

if [ -z "$job_name" ]; then
    >&2 "error: no job name"
    exit 1
fi

export FS_DIR_CACHE_ROOT="$HOME/.cache/fs-dir-cache" # directory to hold all cache (sub)directories
export FS_DIR_CACHE_LOCK_ID="pid-$$-rnd-$RANDOM"     # acquire lock based on the current pid and something random (just in case pid gets reused)
export FS_DIR_CACHE_KEY_NAME="$job_name"             # the base name of our key
export FS_DIR_CACHE_LOCK_TIMEOUT_SECS="$((60 * 30))" # unlock after timeout in case our job fails misereably

log_file="$FS_DIR_CACHE_ROOT/log"

fs-dir-cache gc unused --seconds "$((5 * 24 * 60 * 60))" # delete caches not used in more than a 5 days

# create/reuse cache (sub-directory) and lock it (wait if already locked)
cache_dir=$(fs-dir-cache lock --key-file Cargo.lock --key-str "${CARGO_PROFILE-:dev}" --key-file flake.lock)

export TARGET_DIR="$cache_dir/target"
export CARGO_BUILD_TARGET_DIR="$TARGET_DIR"

>&2 echo "Starting a job=$job_name in cache_dir=$cache_dir"

echo "$(date --rfc-3339=seconds) RUN $cache_dir job=$job_name" >> "$log_file"

on_exit() {
    local exit_code=$?

    fs-dir-cache unlock --dir "${cache_dir}"
    echo "$(date --rfc-3339=seconds) END $cache_dir job=$job_name code=$exit_code" >> "$log_file"

    exit $exit_code
}
trap on_exit EXIT


"$@"
