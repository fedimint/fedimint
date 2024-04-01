#!/usr/bin/env bash

set -euo pipefail

source scripts/_common.sh

ensure_in_dev_shell
build_workspace
add_target_dir_to_path

export DEVIMINT_DIR="${CARGO_BUILD_TARGET_DIR:-target}/devimint"
rm -f "$DEVIMINT_DIR/devimint"

function devimint_env {
  set -euo pipefail

  export RUST_LOG=info
  export RUST_BACKTRACE=1

  # For starship users, we can actually make the prompt distinct so there's
  # no confusion.
  export STARSHIP_CONFIG="${REPO_ROOT}/scripts/dev/devimint-env/starship.toml"

  >&2 echo "Devimint Env Started"
  if [ "$SHELL" == "fish" ] || [[ "$SHELL" == */fish ]]; then
    "${SHELL}"
  else
    # posix shell users can tell they are in devimint-env
    # because we customize the prompt
    if [ -n "${PS1:-}" ]; then
      PS1="[devimint] $PS1"
    else
      PS1="[devimint]"
    fi

    "${SHELL}"
  fi
}
export -f devimint_env

env RUST_LOG="${RUST_LOG:-info,jsonrpsee-client=off}" \
  devimint --link-test-dir "${CARGO_BUILD_TARGET_DIR:-$PWD/target}/devimint" "$@" dev-fed \
    --exec bash -c devimint_env

>&2 echo "Devimint Env Ended"
