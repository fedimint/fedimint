#!/usr/bin/env bash

SIZE="$1"

cargo build

for ((ID=$2; ID<SIZE; ID++)); do
  (target/debug/server cfg/server-$ID.json 2>&1 | sed -e "s/^/mint $ID: /" ) &
done

read -p "Press enter to stop processes"

kill 0