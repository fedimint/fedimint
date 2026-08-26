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

test_dir="$(mktemp -d)"

# Daemons started by a run carry its FM_TEST_DIR in their environment.
function orphans() {
  local name pid
  for name in fedimintd gatewayd bitcoind lnd esplora; do
    for pid in $(pgrep -x "$name" || true); do
      if tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -qx "FM_TEST_DIR=$FM_TEST_DIR"; then
        echo "$name ($pid)"
      fi
    done
  done
}

for cmd in dev-fed wasm-test-setup; do
  >&2 echo "Testing that $cmd tears down after a failed user command"
  export FM_TEST_DIR="$test_dir/$cmd"
  mkdir -p "$FM_TEST_DIR"

  if devimint "$@" "$cmd" --exec false; then
    >&2 echo "devimint $cmd --exec false succeeded, expected it to fail"
    exit 1
  fi

  leftovers="$(orphans)"
  if [ -n "$leftovers" ]; then
    >&2 echo "devimint $cmd --exec false left daemons running:"
    >&2 echo "$leftovers"
    exit 1
  fi
done
