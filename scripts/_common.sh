# shellcheck shell=bash

export REPO_ROOT


if command -v git &> /dev/null; then
  REPO_ROOT="$(git rev-parse --show-toplevel)"
else
  REPO_ROOT="$PWD"
fi



function add_target_dir_to_path() {
  export PATH="${CARGO_BUILD_TARGET_DIR:-$PWD/target}/${CARGO_PROFILE:-debug}:$PATH"
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
  fed_version=$3
  client_version=$5
  gateway_version=$7

  use_fed_binaries_for_version "$fed_version"
  use_client_binaries_for_version "$client_version"
  use_gateway_binaries_for_version "$gateway_version"

  # this is a back-compat test if any version is not current
  if \
    [ "$fed_version" != "current" ] ||
    [ "$client_version" != "current" ] ||
    [ "$gateway_version" != "current" ] ; then
    # signal to downstream test scripts
    export FM_BACKWARDS_COMPATIBILITY_TEST=1
    # run back-compat tests with 4/4 setup
    export FM_OFFLINE_NODES=0
    export FM_RUN_TEST_VERSIONS="FM: $fed_version, CLI: $client_version, GW: $gateway_version"
  else
    # default to run current tests in 3/4 setup
    export FM_OFFLINE_NODES=1
    export FM_DISCOVER_API_VERSION_TIMEOUT=5
    unset FM_RUN_TEST_VERSIONS
  fi

  if [[ ("$client_version"  == "v0.2.1" || "$client_version"  == "v0.2.2" ) && "$fed_version" == "current" ]]; then
    # support(v0.2.1):
    # support(v0.2.2):
    # in the v0.2.1 and v0.2.2 there was a bug crashing client in the presence of unknown modules
    export FM_DISABLE_META_MODULE=1
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

# Generates a matrix of fed, client, and gateway versions using a provided filter
# function and list of versions.
# Parameters:
#   $1 - filter_fn: Function that will filter versions to include in the matrix
#   $2+ - versions: Variadic versions to include (e.g. v0.2.1 v0.2.2)
# Returns: Array of strings where each element is a matrix row of version combinations
function generate_matrix() {
  filter_fn="$1"
  shift

  versions=("$@")
  for fed_version in "${versions[@]}"; do
    for client_version in "${versions[@]}"; do
      for gateway_version in "${versions[@]}"; do
        if "$filter_fn" "$fed_version" "$client_version" "$gateway_version"; then
          # bash doesn't allow returning arrays, however we can mimic the
          # behavior of returning an array by echoing each element
          echo "FM: $fed_version CLI: $client_version GW: $gateway_version"
        fi
      done
    done
  done
}

# Returns true if fed, client, or gateway have a different version.
function is_any_version_different() {
  fed_version="$1"
  client_version="$2"
  gateway_version="$3"
  [ "$fed_version" != "$client_version" ] \
    || [ "$fed_version" != "$gateway_version" ] \
    || [ "$client_version" != "$gateway_version" ]
}

# Returns true if fed, client, and gateway only have one non-"current" version.
function is_only_one_version_not_current() {
  fed_version="$1"
  client_version="$2"
  gateway_version="$3"
  current_count="$(filter_count "current" "$fed_version" "$client_version" "$gateway_version")"
  [ "$current_count" == 2 ]
}

# Returns true if fed, client, and gateway are all "current" versions.
function are_all_versions_current() {
  fed_version="$1"
  client_version="$2"
  gateway_version="$3"
  current_count="$(filter_count "current" "$fed_version" "$client_version" "$gateway_version")"
  [ "$current_count" == 3 ]
}

# Generates a matrix of every version combination except for all binaries on
# the same version. Testing all binaries with the same version is redundant
# since this was covered for that version's "current" release.
# Parameters:
#   $@ - versions: Variadic versions to include (e.g. v0.2.1 v0.2.2)
# Returns: Array of strings where each element is a matrix row of version combinations
#   The return type must be consumed using `mapfile` to correctly read as an array
#   Example call: `mapfile -t version_matrix < <(generate_full_matrix "${versions[@]}")`
function generate_full_matrix() {
  generate_matrix is_any_version_different "$@"
}

# Generates a matrix of every version combination where only one binary is not "current".
#
# This is the default matrix generated in CI since testing only one binary on a previous
# version will cover most of the backwards-incompatible changes and materially increase
# the speed of CI.
#
# For additional context, see: https://github.com/fedimint/fedimint/pull/4389
#
# The following example shows the difference between a full and partial matrix using v0.2.1.
#
# Full:
# v0.2.1  v0.2.1  current
# v0.2.1  current v0.2.1
# v0.2.1  current current
# current v0.2.1  v0.2.1
# current v0.2.1  current
# current current v0.2.1
#
# Partial:
# v0.2.1  current current
# current v0.2.1  current
# current current v0.2.1
#
# Parameters:
#   $@ - versions: Variadic versions to include (e.g. v0.2.1 v0.2.2)
# Returns: Array of strings where each element is a matrix row of version combinations
#   The return type must be consumed using `mapfile` to correctly read as an array
#   Example call: `mapfile -t version_matrix < <(generate_partial_matrix "${versions[@]}")`
function generate_partial_matrix() {
  generate_matrix is_only_one_version_not_current "$@"
}

# Generates a matrix where all versions are "current". This is used for running the
# test suite without backwards-compatibility tests.
# Parameters:
#   $@ - versions: Variadic versions to include (e.g. v0.2.1 v0.2.2)
# Returns: Array of strings where each element is a matrix row of version combinations
#   The return type must be consumed using `mapfile` to correctly read as an array
#   Example call: `mapfile -t version_matrix < <(generate_current_only_matrix "${versions[@]}")`
function generate_current_only_matrix() {
  generate_matrix are_all_versions_current "$@"
}
