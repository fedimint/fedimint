#!/usr/bin/env bash

set -u

echo "Setting up tests..."

FM_FED_SIZE=${1:-4}

source ./scripts/build.sh $FM_FED_SIZE

# start daemons
start_bitcoind
start_electrs
start_esplora
start_lightningd
start_lnd

# Open channel
open_channel
