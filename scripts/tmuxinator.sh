#!/usr/bin/env nix-shell
#!nix-shell -i bash ../shell.nix
# shellcheck shell=bash

set -euo pipefail

if [[ -n "${TMUX:-}" ]]; then
  echo "Can not run tmuxinator in tmux"
  exit 1
fi

source scripts/build.sh
echo "Running in temporary directory $FM_TEST_DIR"

env | sed -En 's/(FM_[^=]*).*/\1/gp' | while read var; do printf 'export %s=%q\n' "$var" "${!var}"; done > .tmpenv

tmuxinator local
tmux -L fedimint-dev kill-session -t fedimint-dev || true
pkill bitcoind
pkill lightningd

rm .tmpenv
