#!/usr/bin/env bash
# Runs a test to determine if upgrading binaries succeeds

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"
source scripts/_common.sh

if [ "$#" -eq 0 ]; then
  echo "Must provide at least one version"
  exit 1
fi


# TODO(v0.5.0): We do not need to run the `gatewayd-mnemonic` test from v0.4.0
# -> v0.5.0 over and over again. Once we have verified this test passes for
# v0.5.0, it can safely be removed.
default_test_kinds=("fedimintd" "fedimint-cli" "gateway" "mnemonic")

# runs a subset of tests if the user provides `TEST_KINDS`
# ex: TEST_KINDS=fedimint-cli,gateway
provided_test_kinds="${TEST_KINDS:-}"
if [ -z "$provided_test_kinds" ]; then
  test_kinds=("${default_test_kinds[@]}")
  echo "no test kinds provided, running for all test kinds"
else
  IFS=',' read -r -a test_kinds<<< "$provided_test_kinds"
  for test_kind in "${test_kinds[@]}"; do
    if ! contains "$test_kind" "${default_test_kinds[@]}"; then
      echo "not a valid test kind: $test_kind"
      exit 1
    fi
  done
fi

build_workspace
add_target_dir_to_path

export FM_BACKWARDS_COMPATIBILITY_TEST=1

upgrade_tests=()

IFS=',' read -r -a version_paths <<< "$@"
for version_path in "${version_paths[@]}"; do
  echo "$version_path"
done

for version_path in "${version_paths[@]}"; do
  IFS=' ' read -r -a versions <<< "$version_path"
  echo "## Running upgrade tests
  versions: ${versions[*]}
  kinds: ${test_kinds[*]}"

  if contains "fedimintd" "${test_kinds[@]}"; then
    fedimintd_paths=()
    for version in "${versions[@]}"; do
      if [ "$version" == "current" ]; then
        # Add current binaries from PATH
        fedimintd_paths+=("fedimintd")
      else
        fedimintd_paths+=("$(nix_build_binary_for_version 'fedimintd' "$version")")
      fi
    done

    upgrade_tests+=(
      "devimint upgrade-tests fedimintd --paths $(printf "%s " "${fedimintd_paths[@]}")"
    )
  fi

  if contains "fedimint-cli" "${test_kinds[@]}"; then
    fedimint_cli_paths=()
    for version in "${versions[@]}"; do
      if [ "$version" == "current" ]; then
        # Add current binaries from PATH
        fedimint_cli_paths+=("fedimint-cli")
      else
        fedimint_cli_paths+=("$(nix_build_binary_for_version 'fedimint-cli' "$version")")
      fi
    done

    upgrade_tests+=(
      "devimint upgrade-tests fedimint-cli --paths $(printf "%s " "${fedimint_cli_paths[@]}")"
    )
  fi

  if contains "gateway" "${test_kinds[@]}"; then
    gatewayd_paths=()
    gateway_cli_paths=()
    for version in "${versions[@]}"; do
      if [ "$version" == "current" ]; then
        # Add current binaries from PATH
        gatewayd_paths+=("gatewayd")
        gateway_cli_paths+=("gateway-cli")
      else
        gatewayd_paths+=("$(nix_build_binary_for_version 'gatewayd' "$version")")
        gateway_cli_paths+=("$(nix_build_binary_for_version 'gateway-cli' "$version")")
      fi
    done

    upgrade_tests+=(
      "devimint upgrade-tests gatewayd --gatewayd-paths $(printf "%s " "${gatewayd_paths[@]}") --gateway-cli-paths $(printf "%s " "${gateway_cli_paths[@]}")"
    )
  fi

  if contains "mnemonic" "${test_kinds[@]}"; then
    old_gatewayd=$(nix_build_binary_for_version 'gatewayd' "v0.4.0")
    new_gatewayd="gatewayd"
    old_gateway_cli=$(nix_build_binary_for_version 'gateway-cli' "v0.4.0")
    new_gateway_cli="gateway-cli"

    upgrade_tests+=(
      "gateway-tests gatewayd-mnemonic --old-gatewayd-path $old_gatewayd --new-gatewayd-path $new_gatewayd --gw-type lnd --old-gateway-cli-path $old_gateway_cli --new-gateway-cli-path $new_gateway_cli"
    )
  fi
done


parsed_test_commands=$(printf "%s\n" "${upgrade_tests[@]}")

tmpdir=$(mktemp --tmpdir -d XXXXX)
trap 'rm -r $tmpdir' EXIT
joblog="$tmpdir/joblog"

parallel_args=()
if [ -z "${CI:-}" ] && [[ -t 1 ]] && [ -z "${FM_TEST_CI_ALL_DISABLE_ETA:-}" ]; then
  parallel_args+=(--eta)
fi
parallel_args+=(--jobs "${FM_TEST_CI_ALL_JOBS:-$(($(nproc) / 4 + 1))}")
parallel_args+=(--load "${FM_TEST_CI_ALL_MAX_LOAD:-$(($(nproc) / 4 + 1))}")
parallel_args+=(--delay "${FM_TEST_CI_ALL_DELAY:-$((64 / $(nproc) + 1))}")
parallel_args+=(
  --halt-on-error 1
  --joblog "$joblog"
  --noswap
  --memfree 2G
  --nice 15
)

>&2 echo "## Starting all tests in parallel..."
>&2 echo "parallel ${parallel_args[*]}"

start=$(date +%s)  # Record start time in nanoseconds

echo "$parsed_test_commands" | if parallel "${parallel_args[@]}"; then
  >&2 echo "All tests successful"
else
  >&2 echo "Some tests failed:"
  awk '{ if($7 != "0") print $0 "\n" }' < "$joblog"
  exit 1
fi

end=$(date +%s)    # Record end time in nanoseconds
runtime=$((end - start)) # Calculate the difference
echo "Runtime: $runtime seconds"

