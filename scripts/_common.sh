# shellcheck shell=bash

function add_target_dir_to_path() {
  export PATH="$PWD/target/${CARGO_PROFILE:-debug}:$PATH"
}

function build_workspace() {
  if [ -z "${SKIP_CARGO_BUILD:-}" ]; then
    cargo build --workspace --all-targets ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}}
  fi
}

# kill the last command spawned in the background (with '&') at the end of a script
# optionally can have name passed
function auto_kill_last_cmd() {
  pid=$!

  # For shellcheck - we want these expanded right away
  # shellcheck disable=SC2064
  trap ">&2 echo 'Auto-killing ${1:-}(PID: $pid) and waiting it to finish...'; kill $pid; wait $pid" EXIT
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
    touch "${TMP:-/tmp}-$(echo "$FM_TEST_NAME" |tr -cd '[:alnum:]-_')" || true
  fi
}
