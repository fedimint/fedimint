#!/usr/bin/env bash

set -euo pipefail

if [[ -z "${IN_NIX_SHELL:-}" ]]; then
  echo "It is recommended to run this command from a Nix dev shell. Use 'nix develop' first"
  sleep 3
fi

# Flag to enable verbose build output from depndent processes (disabled by default)
export FM_VERBOSE_OUTPUT=0

source scripts/build.sh

devimint dev-fed 2>/dev/null &
echo $! >> $FM_PID_FILE
eval "$(devimint env)"

mprocs -c misc/mprocs.yaml
