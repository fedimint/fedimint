#!/usr/bin/env bash

export FM_BITCOIN_NETWORK="regtest"
export FM_FED_SIZE=${1:-2}
export FM_FED_NAME=${2:-"Cypherpunk Federation"}

source scripts/build.sh $FM_FED_SIZE

tail -n +0 -F $FM_LOGS_DIR/fedimintd-0.log &
echo $! >> $FM_PID_FILE
tail -n +0 -F $FM_LOGS_DIR/fedimintd-1.log &
echo $! >> $FM_PID_FILE

fedimint-bin-tests run-ui
