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

function run_test_for_versions() {
  fn_name=$1
  fed_version=$2
  client_version=$3
  gateway_version=$4

  use_fed_binaries_for_version "$fed_version"
  use_client_binaries_for_version "$client_version"
  use_gateway_binaries_for_version "$gateway_version"

  # this is a back-compat test if any version is not current
  if [ "$(filter_count "current" "$fed_version" "$client_version" "$gateway_version")" != 3 ]; then
    # signal to downstream test scripts
    export FM_BACKWARDS_COMPATIBILITY_TEST=1
    # run back-compat tests with 4/4 setup
    export FM_OFFLINE_NODES=0
  else
    # default to run current tests in 3/4 setup
    export FM_OFFLINE_NODES=1
  fi

  $fn_name
}
export -f run_test_for_versions

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
  echo "$(nix build 'github:fedimint/fedimint/'"$version"'#'"$binary" --no-link --print-out-paths)/bin/$binary"
}
export -f nix_build_binary_for_version

function use_fed_binaries_for_version() {
  version=$1
  if [[ "$version" == "current" ]]; then
    unset FM_FEDIMINTD_BASE_EXECUTABLE
  else
    >&2 echo "Compiling fed binaries for version $version..."
    FM_FEDIMINTD_BASE_EXECUTABLE="$(nix_build_binary_for_version 'fedimintd' "$version")"
    export FM_FEDIMINTD_BASE_EXECUTABLE
  fi
}
export -f use_fed_binaries_for_version

function use_client_binaries_for_version() {
  version=$1
  if [[ "$version" == "current" ]]; then
    unset FM_FEDIMINT_CLI_BASE_EXECUTABLE
    unset FM_GATEWAY_CLI_BASE_EXECUTABLE
  else
    >&2 echo "Compiling client binaries for version $version..."
    FM_FEDIMINT_CLI_BASE_EXECUTABLE="$(nix_build_binary_for_version 'fedimint-cli' "$version")"
    export FM_FEDIMINT_CLI_BASE_EXECUTABLE
    FM_GATEWAY_CLI_BASE_EXECUTABLE="$(nix_build_binary_for_version 'gateway-cli' "$version")"
    export FM_GATEWAY_CLI_BASE_EXECUTABLE
  fi
}
export -f use_client_binaries_for_version

function use_gateway_binaries_for_version() {
  version=$1
  if [[ "$version" == "current" ]]; then
    unset FM_GATEWAYD_BASE_EXECUTABLE
  else
    >&2 echo "Compiling gateway binaries for version $version..."
    FM_GATEWAYD_BASE_EXECUTABLE="$(nix_build_binary_for_version 'gatewayd' "$version")"
    export FM_GATEWAYD_BASE_EXECUTABLE
  fi
}
export -f use_gateway_binaries_for_version

