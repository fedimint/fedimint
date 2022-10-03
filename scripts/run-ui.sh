#!/usr/bin/env bash

export FM_FED_SIZE=${1:-4}
# clear out federation startup configs folder
rm -rf $PWD/fed-ui

# start bitcoind on regtest in the background
bitcoind -regtest -daemon -fallbackfee=0.0004 -txindex -server -rpcuser=bitcoin -rpcpassword=bitcoin

# start guardians

for ((ID = 0; ID < $FM_FED_SIZE; ID++)); do
  cargo run --bin fedimintd $PWD/fed-ui/mint-$ID.json $PWD/fed-ui/mint-$ID.db $((10000 + $ID)) &
done

function kill_fedimint_processes {
  pkill "fedimintd" || true
}

trap kill_fedimint_processes EXIT
