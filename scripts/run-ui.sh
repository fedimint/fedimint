#!/usr/bin/env bash

export FM_BITCOIN_NETWORK="regtest"
export FM_FED_SIZE=${1:-2}
export FM_FED_NAME=${2:-"Cypherpunk Federation"}

source scripts/build.sh $FM_FED_SIZE

export RUST_BACKTRACE=1

start_bitcoind | show_verbose_output &
start_federation

echo "UI instances running at http://127.0.0.1:18185 and http://127.0.0.1:18175"

# Allow daemons to keep running
wait
