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
    touch "${TMPDIR:-/tmp}/$(echo "$FM_TEST_NAME" |tr -cd '[:alnum:]-_')" || true
  fi
}

# count number of times the first argument appears in rest of the arguments
function filter_count() {
  item="$1"
  ((count=0))
  shift

  for arg in "$@"; do
    if [ "$arg" == "$item" ]; then
      ((count++))
    fi
  done

  echo "$count"
}
export -f filter_count

function nix_build_binary_for_version() {
  binary="$1"
  version="$2"

  >&2 echo "Compiling ${binary} for version ${version} ..."
  output_path=$(nix build 'github:fedimint/fedimint/'"$version"'#'"$binary" --no-link --print-out-paths) || {
    >&2 echo "Error: nix build failed for $binary $version"
    exit 1
  }
  echo "${output_path}/bin/${binary}"
}
export -f nix_build_binary_for_version

# name of an an env variable to use for a path of a binary compiled by nix for given binary in a given version
function nix_binary_version_var_name() {
  binary="$1"
  version="$2"
  echo "fm_bin_${binary}_${version}" | tr '-' "_" | tr '.' '_'
}
export -f nix_binary_version_var_name

export LNV2_STABLE_VERSION="v0.7.0"
function version_lt() {
  if [ "$1" = "current" ]; then
    return 1
  elif [ "$2" = "current" ]; then
    return 0
  fi

  # replace `-` with `~` so `sort -V` correctly sorts pre-releases
  v1="${1//-/\~}"
  v2="${2//-/\~}"

  [ "$v1" != "$(echo -e "$v1\n$v2" | sort -V | tail -n 1)" ]
}

function supports_lnv2() {
  fed_version=$1
  client_version=$2
  gateway_version=$3

  for version in "$fed_version" "$client_version" "$gateway_version"; do
    if version_lt "$version" "$LNV2_STABLE_VERSION"; then
        return 1
    fi
  done

  return 0
}

# Returns true if the search string is contained in the array
function contains() {
  local search_str="$1"
  shift
  local array=("$@")

  for item in "${array[@]}"; do
    if [[ "$item" == "$search_str" ]]; then
      return 0
    fi
  done
  return 1
}
