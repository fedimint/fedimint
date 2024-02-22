#!/usr/bin/env bash

set -euo pipefail

# versions to test when run without arguments
default_versions=("v0.2.1")
# all versions to use for testing
versions=( "${@:-${default_versions[@]}}" )

>&2 echo "Running backwards-compatibility tests for versions: ${versions[*]}"

# signal to downstream test scripts
export FM_BACKWARDS_COMPATIBILITY_TEST=1

function nix_build_binary_for_version() {
  binary="$1"
  version="$2"
  echo "$(nix build 'github:fedimint/fedimint/'"$version"'#'"$binary" --no-link --print-out-paths)/bin/$binary"
}

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

test_results="fed_version,client_version,gateway_version,exit_code\n"
has_failure=false
versions+=("current")

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

for fed_version in "${versions[@]}"; do
  for client_version in "${versions[@]}"; do
    for gateway_version in "${versions[@]}"; do

      # we only need to try everything against one element being in a different version
      if [ "$(filter_count "current" "$fed_version" "$client_version" "$gateway_version")" != 2 ]; then
         continue
      fi

      use_fed_binaries_for_version "$fed_version"
      use_client_binaries_for_version "$client_version"
      use_gateway_binaries_for_version "$gateway_version"

      >&2 echo "========== Starting backwards-compatibility run ==========="
      >&2 echo "fed version: $fed_version"
      >&2 echo "client version: $client_version"
      >&2 echo "gateway version: $gateway_version"

      # continue running against other versions if there's a failure
      set +e
      (./scripts/tests/test-ci-all.sh)
      exit_code=$?
      set -e
      test_results="$test_results$fed_version,$client_version,$gateway_version,$exit_code\n"
      if [[ "$exit_code" -gt 0 ]]; then
        has_failure=true
      fi

      # cleair=$(dirname "$(mktemp -u)")
      rm -rf "${TMPDIR:-/tmp}"/devimint-*

      >&2 echo "========== Finished backwards-compatibility run ==========="
      >&2 echo "fed version: $fed_version"
      >&2 echo "client version: $client_version"
      >&2 echo "gateway version: $gateway_version"
    done
  done
done

>&2 echo "Backwards-compatibility tests summary:"
echo -e "$test_results" | >&2 column -t -s ','

if [[ "$has_failure" == "true" ]]; then
  exit 1
fi
