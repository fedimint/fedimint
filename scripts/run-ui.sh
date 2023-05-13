#!/usr/bin/env bash

export FM_BITCOIN_NETWORK="regtest"
export FM_UI_KIND=${1:-"old"}
export FM_FED_SIZE=${2:-2}
export FM_FED_NAME=${3:-"Cypherpunk Federation"}
export RUST_BACKTRACE="full"

source scripts/build.sh $FM_FED_SIZE

for ((i=0; i < FM_FED_SIZE; i++));
do
  echo $i
  tail -n +0 -F "$FM_LOGS_DIR/fedimintd-$i.log" &
  echo $! >> $FM_PID_FILE
done

devimint run-ui $FM_UI_KIND
