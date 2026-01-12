#!/usr/bin/env bash

set -euo pipefail

source scripts/_common.sh

ensure_in_dev_shell
build_workspace
add_target_dir_to_path

function devimintd_env {
  set -euo pipefail

  export RUST_LOG=info
  export RUST_BACKTRACE=1

  source "${REPO_ROOT}/scripts/dev/aliases.sh"
  export PROMPT_ENV_INDICATOR
  if [ -n "${PROMPT_ENV_INDICATOR:-}" ]; then
    PROMPT_ENV_INDICATOR="devimintd $PROMPT_ENV_INDICATOR"
  else
    PROMPT_ENV_INDICATOR="devimintd"
  fi

  >&2 echo "Devimintd Env Shell Ready (exit to shutdown):"
  if [ "$SHELL" == "fish" ] || [[ "$SHELL" == */fish ]]; then
    "${SHELL}"
  else
    if [ -n "${PS1:-}" ]; then
      PS1="[devimintd] $PS1"
    else
      PS1="[devimintd]"
    fi

    "${SHELL}"
  fi
}
export -f devimintd_env

env RUST_LOG="${RUST_LOG:-info,jsonrpsee-client=off}" \
  devimintd "$@" bash -c devimintd_env

>&2 echo "Devimintd Env Ended"
