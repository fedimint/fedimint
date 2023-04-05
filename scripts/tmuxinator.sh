#!/usr/bin/env bash

set -euo pipefail

if [[ -n "${TMUX:-}" ]]; then
  echo "Can not run tmuxinator in tmux"
  exit 1
fi

if [[ -z "${IN_NIX_SHELL:-}" ]]; then
  echo "It is recommended to run this command from a Nix dev shell. Use 'nix develop' first"
  sleep 3
fi

# Flag to enable verbose build output from depndent processes (disabled by default)
export FM_VERBOSE_OUTPUT=0

source scripts/build.sh
echo "Running in temporary directory $FM_TEST_DIR"

# a pipe that rust writes to, and user-shell can wait for it
export FM_READY_FILE=$FM_TMP_DIR/ready
mkfifo $FM_READY_FILE

$FM_BIN_DIR/fedimint-bin-tests tmuxinator &>$FM_LOGS_DIR/fedimint-dev.log &
echo $! >> $FM_PID_FILE

env | sed -En 's/^(FM_[^=]*).*/\1/gp' | while read var; do printf 'export %s=%q\n' "$var" "${!var}"; done > .tmpenv

SHELL=$(which bash) tmuxinator local
tmux -L fedimint-dev kill-session -t fedimint-dev || true

rm .tmpenv
