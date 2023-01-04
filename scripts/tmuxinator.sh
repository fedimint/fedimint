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

env | sed -En 's/(FM_[^=]*).*/\1/gp' | while read var; do printf 'export %s=%q\n' "$var" "${!var}"; done > .tmpenv

export FEDIMINT_BITCOIND_RPC="http://bitcoin:bitcoin@127.0.0.1:18443" # default bitcoind rpc port for regtest
SHELL=$(which bash) tmuxinator local
tmux -L fedimint-dev kill-session -t fedimint-dev || true
pkill bitcoind
pkill lightningd

rm .tmpenv
