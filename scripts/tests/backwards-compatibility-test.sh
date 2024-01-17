#!/usr/bin/env bash

set -euo pipefail

# all versions to use for testing
versions=("v0.2.1")
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
for fed_version in "${versions[@]}"; do
  for client_version in "${versions[@]}"; do
    for gateway_version in "${versions[@]}"; do
      # test-ci-all already tests binaries running the same version, so no need to run again
      if [[ "$fed_version" == "$client_version" && "$fed_version" == "$gateway_version" ]]; then
        continue
      fi

      use_fed_binaries_for_version "$fed_version"
      use_client_binaries_for_version "$client_version"
      use_gateway_binaries_for_version "$gateway_version"

      >&2 echo "========== Starting backwards-compatibility run ==========="
      >&2 echo "fed version: $fed_version"
      >&2 echo "client version: $client_version"
      >&2 echo "gateway version: $gateway_version"
      >&2 df -h
      >&2 nix run nixpkgs#du-dust /

      # continue running against other versions if there's a failure
      set +e
      (./scripts/tests/test-ci-all.sh)
      exit_code=$?
      set -e
      test_results="$test_results$fed_version,$client_version,$gateway_version,$exit_code\n"
      [[ "$exit_code" -gt 0 ]] && has_failure=true

      >&2 echo "========== Finished backwards-compatibility run ==========="
      >&2 echo "fed version: $fed_version"
      >&2 echo "client version: $client_version"
      >&2 echo "gateway version: $gateway_version"
      >&2 df -h
      >&2 nix run nixpkgs#du-dust /
    done
  done
done

>&2 echo "Backwards-compatibility tests summary:"
echo -e "$test_results" | >&2 column -t -s ','
# CI requires explicitly exiting with an error or success code
[[ "$has_failure" == "true" ]] && exit 1 || exit 0
