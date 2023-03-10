#!/usr/bin/env bash

export FM_FED_SIZE=${1:-2}
# clear out federation startup configs folder
rm -r $PWD/fed-ui
mkdir $PWD/fed-ui

# start bitcoind on regtest in the background
export FM_BITCOIND_RPC="http://bitcoin:bitcoin@127.0.0.1:18443"
bitcoind -datadir=$FM_BTC_DIR &

# start guardians
for ((ID = 0; ID < $FM_FED_SIZE; ID++)); do
  mkdir $PWD/fed-ui/mock-$ID
  p2p_port=$((10000 + 10000 * $ID))
  api_port=$((10001 + 10000 * $ID))
  export FM_BIND_P2P=127.0.0.1:$p2p_port
  export FM_P2P_URL=fedimint://127.0.0.1:$p2p_port
  export FM_BIND_API=127.0.0.1:$api_port
  export FM_API_URL=ws://127.0.0.1:$api_port
  cargo run --bin fedimintd $PWD/fed-ui/mock-$ID pw-$ID --listen-ui 127.0.0.1:$((19800 + $ID)) &
done

function kill_fedimint_processes {
  pkill "fedimintd" || true
}

trap kill_fedimint_processes EXIT
