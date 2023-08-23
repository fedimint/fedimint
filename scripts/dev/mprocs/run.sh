#!/usr/bin/env bash

set -euo pipefail

if [[ -z "${IN_NIX_SHELL:-}" ]]; then
  echo "It is recommended to run this command from a Nix dev shell. Use 'nix develop' first"
  sleep 3
fi

# Flag to enable verbose build output from depndent processes (disabled by default)
export FM_VERBOSE_OUTPUT=0

source scripts/lib.sh
source scripts/build.sh

mkdir -p $FM_LOGS_DIR

devimint dev-fed 2>$FM_LOGS_DIR/devimint-outer.log &
pid=$!
kill_on_exit $pid dev-fed
PIDS+=( "$pid" )

eval "$(devimint env)"

mprocs -c misc/mprocs.yaml
kill "${PIDS[@]}"
wait "${PIDS[@]}"
