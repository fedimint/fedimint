#!/usr/bin/env bash
# A failing user command must still tear down every daemon devimint started and
# exit non-zero, instead of leaving them to whatever the tokio runtime shutdown
# makes of them (see #9065).

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

# Processes started by a run carry its FM_TEST_DIR in their environment.
function leaked_processes() {
  local pid
  for pid in $(pgrep -u "$(id -u)"); do
    if [ "$pid" != "$$" ] && grep -qzxF "FM_TEST_DIR=$FM_TEST_DIR" "/proc/$pid/environ" 2>/dev/null; then
      echo "$pid $(cat "/proc/$pid/comm" 2>/dev/null)"
    fi
  done
}

for cmd in dev-fed wasm-test-setup; do
  >&2 echo "Testing that $cmd tears down after a failed user command"
  # Under the per-test TMPDIR and named like devimint's own directories, so
  # that fm-run-test finds the daemon logs on failure.
  FM_TEST_DIR="$(mktemp -d --tmpdir "devimint-$cmd-XXXXXX")"
  export FM_TEST_DIR
  marker="$FM_TEST_DIR/user-command-ran"

  if devimint "$@" "$cmd" --exec sh -c "touch '$marker' && exit 1"; then
    >&2 echo "devimint $cmd with a failing user command succeeded, expected it to fail"
    exit 1
  fi
  if [ ! -e "$marker" ]; then
    >&2 echo "devimint $cmd failed before running the user command"
    exit 1
  fi

  leaked="$(leaked_processes)"
  if [ -n "$leaked" ]; then
    >&2 echo "devimint $cmd left processes running, killing them:"
    >&2 echo "$leaked"
    echo "$leaked" | awk '{ print $1 }' | xargs -r kill
    exit 1
  fi
done
