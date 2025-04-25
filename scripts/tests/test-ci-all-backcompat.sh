#!/usr/bin/env bash

# previous versions did not have unknown module so can't support it,
# disable devimint enabling it in Federations
export FM_USE_UNKNOWN_MODULE=0

export RUST_LOG=${RUST_LOG:-h2=off,fm=debug,info}

nix run nixpkgs#stress-ng -- \
  --cpu "$(nproc)" \
  --vm 1 --vm-bytes 60% \
  --timeout 300s \
  --metrics-brief \
  &

echo "started stress-ng in background"

sleep 5

./scripts/tests/test-ci-all.sh "$@"

