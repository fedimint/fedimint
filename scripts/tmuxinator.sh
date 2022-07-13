#! /usr/bin/env nix-shell
#! nix-shell -i bash ../shell.nix

set -euo pipefail

source scripts/build.sh
echo "Running in temporary directory $FM_TEST_DIR"

env | sed -En 's/(FM_[^=]*).*/\1/gp' | while read var; do printf 'export %s=%q\n' "$var" "${!var}"; done > .tmpenv

tmuxinator local
tmux kill-session -t fedimint-dev || true
pkill bitcoind
pkill lightningd

rm .tmpenv