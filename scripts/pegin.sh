#!/usr/bin/env bash

set -e

BTC_CLI="bitcoin-cli -regtest -rpcconnect=127.0.0.1 -rpcuser=bitcoin -rpcpassword=bitcoin"
CLIENT="cargo run --release --bin mint-client cfg"

ADDR="$($CLIENT peg-in-address)"
TX_ID="$($BTC_CLI sendtoaddress $ADDR $1)"
$BTC_CLI generatetoaddress 11 "$($BTC_CLI getnewaddress)"
TXOUT_PROOF="$($BTC_CLI gettxoutproof "[\"$TX_ID\"]")"
TRANSACTION="$($BTC_CLI getrawtransaction $TX_ID)"
echo waiting 10 seconds for the mints to process the blocks
sleep 10
$CLIENT peg-in "$TXOUT_PROOF" "$TRANSACTION"
$CLIENT fetch
