#!/usr/bin/env bash

export FM_FED_SIZE=${1:-2}
# clear out federation startup configs folder
rm -r $PWD/fed-ui
mkdir $PWD/fed-ui

# start bitcoind on regtest in the background
bitcoind -regtest -daemon -fallbackfee=0.0004 -txindex -server -rpcuser=bitcoin -rpcpassword=bitcoin

# start guardians
for ((ID = 0; ID < $FM_FED_SIZE; ID++)); do
  mkdir $PWD/fed-ui/mock-$ID
  cargo run --bin fedimintd $PWD/fed-ui/mock-$ID pw-$ID --listen-ui 127.0.0.1:$((19800 + $ID)) &
done

function kill_fedimint_processes {
  pkill "fedimintd" || true
}

trap kill_fedimint_processes EXIT
