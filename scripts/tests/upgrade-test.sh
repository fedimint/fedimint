#!/usr/bin/env bash
# Runs a test to determine if upgrading binaries succeeds

set -euo pipefail

export RUST_LOG="${RUST_LOG:-info}"

# Older version might not support iroh
export FM_ENABLE_IROH=false

source scripts/_common.sh

if [ "$#" -eq 0 ]; then
  echo "Must provide at least one version"
  exit 1
fi

PATH="$(pwd)/scripts/dev/run-test/:$PATH"

# Upgrade tests can take its time, so we need to customize timeout
# used in fm-run-test to be slightly less than the timeout we put on
# every 'parallel' job.
export FM_TEST_UPGRADE_TIMEOUT=${FM_TEST_UPGRADE_TIMEOUT:-800}
export FM_RUN_TEST_TIMEOUT=$((FM_TEST_UPGRADE_TIMEOUT - 30))

default_test_kinds=("fedimintd" "fedimint-cli" "gateway")

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

IFS=',' read -r -a upgrade_paths <<< "$@"

echo "## Running upgrade tests
kinds: ${test_kinds[*]}
upgrade paths:"

for upgrade_path in "${upgrade_paths[@]}"; do
  echo "$upgrade_path"
done

for upgrade_path in "${upgrade_paths[@]}"; do
  IFS=' ' read -r -a versions <<< "$upgrade_path"
  echo "## Starting upgrade test for path: $upgrade_path"
  versions_str=$(IFS=,; echo "${versions[*]}")
  first_version="${versions[0]}"

  if version_lt "$first_version" "$LNV2_STABLE_VERSION"; then
    lnv2_flags=(0)
  else
    lnv2_flags=(0 1)
  fi

  if contains "fedimintd" "${test_kinds[@]}"; then
    fedimintd_paths=()
    for version in "${versions[@]}"; do
      if [ "$version" == "current" ]; then
        # Add current binaries from PATH
        fedimintd_paths+=("fedimintd")
      else
        # for dkg we need to use the fedimint-cli version that matches fedimintd
        var_name=$(nix_binary_version_var_name "fedimint-cli" "$version")
        export "${var_name}=$(nix_build_binary_for_version "fedimint-cli" "$version")"

        var_name=$(nix_binary_version_var_name "fedimintd" "$version")
        export "${var_name}=$(nix_build_binary_for_version "fedimintd" "$version")"
        fedimintd_paths+=("${!var_name}")
      fi
    done

    for enable_lnv2 in "${lnv2_flags[@]}"; do
      upgrade_tests+=(
        "fm-run-test fedimintd-${versions_str}-lnv2-${enable_lnv2} devimint upgrade-tests --lnv2 $enable_lnv2 fedimintd --paths $(printf "%s " "${fedimintd_paths[@]}")"
      )
    done
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

    for enable_lnv2 in "${lnv2_flags[@]}"; do
      upgrade_tests+=(
        "fm-run-test fedimint-cli-${versions_str}-lnv2-${enable_lnv2} devimint upgrade-tests --lnv2 $enable_lnv2 fedimint-cli --paths $(printf "%s " "${fedimint_cli_paths[@]}")"
      )
    done
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

    for enable_lnv2 in "${lnv2_flags[@]}"; do
      upgrade_tests+=(
        "fm-run-test gateway-${versions_str}-lnv2-${enable_lnv2} devimint upgrade-tests --lnv2 $enable_lnv2 gatewayd --gatewayd-paths $(printf "%s " "${gatewayd_paths[@]}") --gateway-cli-paths $(printf "%s " "${gateway_cli_paths[@]}")"
      )
    done
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
parallel_args+=(--timeout "$FM_TEST_UPGRADE_TIMEOUT")
parallel_args+=(
  --halt-on-error 1
  --joblog "$joblog"
  --noswap
  --memfree 2G
  --nice 15
)

>&2 echo "## Starting all tests in parallel..."
>&2 echo "parallel ${parallel_args[*]}"

echo "$parsed_test_commands" | if parallel "${parallel_args[@]}"; then
  >&2 echo "All tests successful"
else
  >&2 echo "Some tests failed:"
  awk '{ if($7 != "0") print $0 "\n" }' < "$joblog"
  exit 1
fi
