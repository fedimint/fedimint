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
export FM_LOGS_DIR="$FM_TEST_DIR/logs"

echo "Setting up env variables in $FM_TEST_DIR"

mkdir -p "$FM_TEST_DIR"

# Symlink $FM_TEST_DIR to local gitignored target/ directory so they're easier to find
rm -f target/devimint
mkdir -p target
ln -s $FM_TEST_DIR target/devimint

# Builds the rust executables and sets environment variables
SRC_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
cd $SRC_DIR || exit 1
# Note: Respect 'CARGO_PROFILE' that crane uses

if [ -z "${SKIP_CARGO_BUILD:-}" ]; then
  cargo build --workspace --all-targets ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}}
fi
export PATH="$PWD/target/${CARGO_PROFILE:-debug}:$PATH"

function kill_devimint {
  echo "Killing devimint and child processes"
  pkill devimint
}

trap kill_devimint EXIT
