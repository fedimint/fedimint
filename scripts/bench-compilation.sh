#!/usr/bin/env bash

set -euo pipefail

root="$(git rev-parse --show-toplevel)"

if [ -n "${BENCH_COMP_REUSE_TARGET_DIR:-}" ]; then
  export CARGO_BUILD_TARGET_DIR="${CARGO_BUILD_TARGET_DIR:-./target}"
else
  # Use a custom target dir, not to interfere
  export CARGO_BUILD_TARGET_DIR="${root}/target-comp-bench"
fi

# Disable sccache
unset RUSTC_WRAPPER

cmd_out_path="$CARGO_BUILD_TARGET_DIR/cmd.out"

on_error() {
  >&2 echo "Error! Results might be invalid."
  if [ -f "$cmd_out_path" ]; then
    >&2 echo "Command error:"
    >&2 cat "$cmd_out_path"
  fi
}

on_exit() {
  if [ -z "${BENCH_COMP_REUSE_TARGET_DIR:-}" ]; then
    rm -Rf "$CARGO_BUILD_TARGET_DIR"
  fi
}
trap on_error ERR
trap on_exit EXIT


cargo fetch

if [ -z "${BENCH_COMP_SKIP_DECORATIONS:-}" ]; then
  nix run nixpkgs#neofetch -- --stdout

  echo "Date: $(date +%Y-%m-%d)"
  echo "Commit: $(git rev-parse --short HEAD)"
fi

time_pipe_path="$CARGO_BUILD_TARGET_DIR/time.out"
time_fmt='%e\t%U\t%S'

echo -e "                       total    user     sys"
for profile in dev release ; do
  for command in check build ; do

    if echo "$BENCH_COMP_SKIP_PROFILE" | grep -wq "$profile"; then
      continue
    fi

    if echo "$BENCH_COMP_SKIP_COMMAND" | grep -wq "$command"; then
      continue
    fi

    profile_human=$profile
    if [ "$profile" = "dev" ]; then
      profile_human="debug"
    fi

    if [ -n "${BENCH_COMP_SKIP_FULL:-}" ]; then
      cargo $command --profile $profile -q  1>/dev/null 2>&1
    else
      rm -Rf "$CARGO_BUILD_TARGET_DIR"
      mkdir -p "$CARGO_BUILD_TARGET_DIR"

      printf "Full %6s %7s:" "$command" "$profile_human"
      command time --format="$time_fmt" -o "$time_pipe_path" -- \
        cargo $command --profile $profile -q  1>"$cmd_out_path" 2>&1
      awk 'BEGIN {FS="\t"} {printf "%8.2f%8.2f%8.2f\n", $1, $2, $3}' < "$time_pipe_path"
    fi

    printf "Incr %6s %7s:" "$command" "$profile_human"
    find "${BENCH_COMP_TOUCH_DIR:-fedimint-core}" -type f -exec touch {} +
    command time --format="$time_fmt" -o "$time_pipe_path" -- \
      cargo $command --profile $profile -q 1>"$cmd_out_path" 2>&1
    awk 'BEGIN {FS="\t"} {printf "%8.2f%8.2f%8.2f\n", $1, $2, $3}' < "$time_pipe_path"

  done
done


if [ -z "${BENCH_COMP_SKIP_DECORATIONS:-}" ]; then
  >&2 echo "Success. Feel free to post on https://github.com/fedimint/fedimint/wiki/Benchmark-compilation-times"
fi
