#!/usr/bin/env bash

SIZE="$1"
PIDS=()

cargo build

for ((ID=$2; ID<SIZE; ID++)); do
  (RUST_LOG=debug target/debug/server $SIZE $ID 5000 2>&1 | sed -e "s/^/mint $ID: /" ) &
  PIDS+=( "$!" )
done

read -p "Press enter to stop processes"

for PID in "${PIDS[@]}"; do
  kill $PID
done