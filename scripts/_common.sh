# shellcheck shell=bash

export REPO_ROOT

if [[ ! $- =~ e ]] || [[ ! $- =~ u ]] || ! (set -o | grep -q "pipefail[[:space:]]*on") ; then
  >&2 echo "Warning: 'set -euo pipefail' is not fully enabled."
fi

if [ -z "${REPO_ROOT:-}" ]; then
  if command -v git &> /dev/null; then
    REPO_ROOT="$(git rev-parse --show-toplevel)"
  else
    REPO_ROOT="$PWD"
  fi

  PATH="$REPO_ROOT/bin:$PATH"
fi


if [ -z "${CARGO_PROFILE:-}" ]; then
  export CARGO_PROFILE="dev"
fi

if [ "$CARGO_PROFILE" = "dev" ]; then
  export CARGO_PROFILE_DIR="debug"
else
  export CARGO_PROFILE_DIR="$CARGO_PROFILE"
fi

export CARGO_BUILD_TARGET_DIR="${CARGO_BUILD_TARGET_DIR:-"$REPO_ROOT/target"}"
export CARGO_BUILD_TARGET_BIN_DIR="${CARGO_BUILD_TARGET_DIR:-$PWD/target}/${CARGO_PROFILE_DIR:-debug}"

function add_target_dir_to_path() {
  export PATH="${CARGO_BUILD_TARGET_BIN_DIR}:$PATH"
}

function build_workspace() {
  if [ -z "${SKIP_CARGO_BUILD:-}" ]; then
    runLowPrio cargo build --workspace --all-targets ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}}
      else
    >&2 echo "SKIP_CARGO_BUILD set, skipping building workspace"
  fi
}

function build_workspace_tests() {
  if [ -z "${SKIP_CARGO_BUILD:-}" ]; then
    runLowPrio cargo nextest run --no-run ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --workspace --all-targets

  else
    >&2 echo "SKIP_CARGO_BUILD set, skipping building workspace tests"
  fi
}

function ensure_in_dev_shell() {
  if [[ -z "${IN_NIX_SHELL:-}" ]]; then
    echo "It is recommended to run this command from a Nix dev shell. Use 'nix develop' first"
    sleep 3
  fi
}

function make_fm_test_marker() {
  if [ -n "${FM_TEST_NAME:-}" ]; then
    # make it easy to identify which tmp dir belongs to which test
    touch "${TMPDIR:-/tmp}/$(echo "$FM_TEST_NAME" |tr -cd '[:alnum:]-_')" || true
  fi
}
