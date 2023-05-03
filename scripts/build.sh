#!/usr/bin/env bash

echo "Run with 'source ./scripts/build.sh [fed_size] [dir]"

# allow for overriding arguments
export FM_FED_SIZE=${1:-4}

# If $TMP contains '/nix-shell.' it is already unique to the
# nix shell instance, and appending more characters to it is
# pointless. It only gets us closer to the 108 character limit
# for named unix sockets (https://stackoverflow.com/a/34833072),
# so let's not do it.

if [[ "${TMP:-}" == *"/nix-shell."* ]]; then
  FM_TEST_DIR="${2-$TMP}/fm-$(LC_ALL=C tr -dc A-Za-z0-9 </dev/urandom | head -c 4 || true)"
else
  FM_TEST_DIR="${2-"$(mktemp --tmpdir -d XXXXX)"}"
fi
export FM_TEST_DIR
export FM_PID_FILE="$FM_TEST_DIR/.pid"
export FM_POLL_INTERVAL=1

echo "Setting up env variables in $FM_TEST_DIR"

mkdir -p "$FM_TEST_DIR"
touch "$FM_PID_FILE"

# Builds the rust executables and sets environment variables
SRC_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
cd $SRC_DIR || exit 1
# Note: Respect 'CARGO_PROFILE' that crane uses
cargo build ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}}
export PATH="$PWD/target/$CARGO_PROFILE:$PATH"


# Function for killing processes stored in FM_PID_FILE in reverse-order they were created in
function kill_fedimint_processes {
  echo "Killing fedimint processes"
  PIDS=$(cat $FM_PID_FILE | sed '1!G;h;$!d') # sed reverses order
  if [ -n "$PIDS" ]
  then
    kill $PIDS 2>/dev/null
  fi
  rm -f $FM_PID_FILE
}

trap kill_fedimint_processes EXIT
