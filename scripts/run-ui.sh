#!/usr/bin/env bash

set -euo pipefail

if [[ -z "${FEDIMINT_UI_SHELL:-}" ]]; then
  echo 'It is recommended to run this script from the fedimint-ui Nix dev shell. Use "nix develop .#fedimint-ui" first.'
  exit 1
fi

export FM_BITCOIN_NETWORK="regtest"
export FM_FED_SIZE=${1:-2}
export FM_FED_NAME=${2:-"Cypherpunk Federation"}

source scripts/build.sh $FM_FED_SIZE

for ((i=0; i < FM_FED_SIZE; i++));
do
  echo $i
  tail -n +0 -F "$FM_LOGS_DIR/fedimintd-$i.log" &
  echo $! >> $FM_PID_FILE
done

devimint run-ui
