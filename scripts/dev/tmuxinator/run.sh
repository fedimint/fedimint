#!/usr/bin/env bash

set -euo pipefail


if [[ -n "${TMUX:-}" ]]; then
  echo "Can not run inside existing tmux session"
  exit 1
fi

source scripts/_common.sh

ensure_in_dev_shell
build_workspace
add_target_dir_to_path

function run_tmuxinator {
  set -euo pipefail

  tmuxinator local
  tmux -L fedimint-dev kill-session -t fedimint-dev || true
}
export -f run_tmuxinator

SHELL=$(which bash) devimint  --link-test-dir ./target/devimint dev-fed --exec bash -c run_tmuxinator
