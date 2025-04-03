#!/usr/bin/env bash

set -euo pipefail

# get the number of memory upfront, just to verify
# it works, can be moved down in the future
if [ "$(uname)" = "Darwin" ]; then
    total=$(sysctl -n hw.memsize)
    total_mbs=$((total / 1024 / 1024))
else
    total=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    total_mbs=$((total / 1024))
fi

>&2 echo "Memory available: $total_mbs"

# Don't mess with non-release builds
if [ "${CARGO_PROFILE:-}" != "release" ]; then
  >&2 echo "Will not limit number of jobs on non-release cargo build profile: ${CARGO_PROFILE:-}"
  exec cargo "$@"
fi


# substract some fixed amount for fixed overhead, then divide by
# approximation of how much one heavy compilation unit needs,
# add +1 to round up
max_jobs_by_memory=$(((total_mbs - 10000) / 7000 + 1))

# handle underflow
if [ "$max_jobs_by_memory" -lt 1 ]; then
  max_jobs_by_memory=1
fi

ncpus=$(nproc)

if [ "$ncpus" -lt "$max_jobs_by_memory" ]; then
  export CARGO_BUILD_JOBS="$ncpus"
else
  export CARGO_BUILD_JOBS="$max_jobs_by_memory"
fi

>&2 echo "Overriding cargo max jobs to: $CARGO_BUILD_JOBS"
exec cargo "$@"
