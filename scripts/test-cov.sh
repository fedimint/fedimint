#!/usr/bin/env bash

#
# Shows a table with the number of tests for each package
#

set -eu

# create array of all possible package targets
mapfile -t packages < <(cargo test -p 2>&1 | rg '^\s+(.+)$' -r '$1')

# we set pipefail here as `cargo test -p` above returns a failure exit code
set -o pipefail

# create nice table header
printf "%-30s: %s\n" "packages" "tests"
printf "%0.s-" {1..30}
printf ":"
printf "%0.s-" {1..15}
printf "\n"

for package in "${packages[@]}"; do
  # --all-targets does not run doc tests
  test_counts=$(cargo test -p "$package" --all-targets 2>/dev/null | rg 'running (\d+) tests?'  -r '$1')

  # add all numbers in `$test_counts`
  total=$(echo -n "$test_counts" | xargs | tr ' ' '+' | bc -l)

  printf "%-30s: %-3s\n" "$package" "$total"
done
