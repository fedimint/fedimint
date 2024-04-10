#!/usr/bin/env bash
# Runs a test to determine if upgrading binaries succeeds

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

if [ "$#" -eq 0 ]; then
  echo "Must provide at least one version"
  exit 1
fi

versions=("$@")

source scripts/_common.sh
build_workspace
add_target_dir_to_path

export FM_BACKWARDS_COMPATIBILITY_TEST=1

fedimintd_paths=()
fedimint_cli_paths=()
gatewayd_paths=()
for version in "${versions[@]}"; do
  fedimintd_paths+=("$(nix_build_binary_for_version 'fedimintd' "$version")")
  fedimint_cli_paths+=("$(nix_build_binary_for_version 'fedimint-cli' "$version")")
  gatewayd_paths+=("$(nix_build_binary_for_version 'gatewayd' "$version")")
done

# Add current binaries from PATH
fedimintd_paths+=("fedimintd")
fedimint_cli_paths+=("fedimint-cli")
gatewayd_paths+=("gatewayd")

upgrade_tests=(
  "devimint upgrade-tests fedimintd --paths $(printf "%s " "${fedimintd_paths[@]}")"
  "devimint upgrade-tests fedimint-cli --paths $(printf "%s " "${fedimint_cli_paths[@]}")"
  "devimint upgrade-tests gatewayd --paths $(printf "%s " "${gatewayd_paths[@]}")"
)

parsed_test_commands=$(printf "%s\n" "${upgrade_tests[@]}")

tmpdir=$(mktemp --tmpdir -d XXXXX)
trap 'rm -r $tmpdir' EXIT
joblog="$tmpdir/joblog"

parallel_args=()
if [ -z "${CI:-}" ] && [[ -t 1 ]] && [ -z "${FM_TEST_CI_ALL_DISABLE_ETA:-}" ]; then
  parallel_args+=(--eta)
fi
parallel_args+=(--jobs "${FM_TEST_CI_ALL_JOBS:-$(($(nproc) / 4 + 1))}")
parallel_args+=(--load "${FM_TEST_CI_ALL_MAX_LOAD:-1000}")
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

echo "$parsed_test_commands" | if parallel "${parallel_args[@]}"; then
  >&2 echo "All tests successful"
else
  >&2 echo "Some tests failed:"
  awk '{ if($7 != "0") print $0 "\n" }' < "$joblog"
  exit 1
fi
