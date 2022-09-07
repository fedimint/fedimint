#!/usr/bin/env bash

set -euo pipefail

if [[ -n "${TMUX:-}" ]]; then
  echo "Can not run tmuxinator in tmux"
  exit 1
fi

if [[ -z "$IN_NIX_SHELL" ]]; then
  echo "It is recommended to run this command from a Nix dev shell. Use `nix develop` first"
  sleep 3
fi

source scripts/build.sh
echo "Running in temporary directory $FM_TEST_DIR"

env | sed -En 's/(FM_[^=]*).*/\1/gp' | while read var; do printf 'export %s=%q\n' "$var" "${!var}"; done > .tmpenv

SHELL=$(which bash) tmuxinator local
tmux -L fedimint-dev kill-session -t fedimint-dev || true
pkill bitcoind
pkill lightningd

rm .tmpenv
