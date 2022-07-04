#!/usr/bin/env bash

FED_SIZE=${1:-4}
SKIPPED_SERVERS=${2:-0}

cargo build --release --bin server

bitcoind -regtest -fallbackfee=0.0004 -txindex -server -rpcuser=bitcoin -rpcpassword=bitcoin &

echo "Waiting for bitcoind to start"
sleep 3

lightningd --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=ln1 --addr=127.0.0.1:9000 &
lightningd --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=ln2 --addr=127.0.0.1:9001 &

for ((ID=SKIPPED_SERVERS; ID<FED_SIZE; ID++)); do
  echo "starting mint $ID"
  (target/release/server cfg/server-$ID.json 2>&1 | sed -e "s/^/mint $ID: /" ) &
done

wait

kill 0