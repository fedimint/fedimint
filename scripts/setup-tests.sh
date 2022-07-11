#!/usr/bin/env bash

set -u

# Starts Bitcoin and 2 LN nodes, opening a channel between the LN nodes
POLL_INTERVAL=1

# Start bitcoind and wait for it to become ready
bitcoind -regtest -fallbackfee=0.0004 -txindex -server -rpcuser=bitcoin -rpcpassword=bitcoin -datadir=$BTC_DIR &
echo $! >> $PID_FILE

until [ "$($BTC_CLIENT getblockchaininfo | jq -r '.chain')" == "regtest" ]; do
  sleep $POLL_INTERVAL
done
$BTC_CLIENT createwallet ""

# Start lightning nodes
lightningd --dev-fast-gossip --dev-bitcoind-poll=1 --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=$LN1_DIR --addr=127.0.0.1:9000 --plugin=$BIN_DIR/ln_gateway --minimint-cfg=$CFG_DIR &
echo $! >> $PID_FILE
lightningd --dev-fast-gossip --dev-bitcoind-poll=1 --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=$LN2_DIR --addr=127.0.0.1:9001 &
echo $! >> $PID_FILE
until [ -e $LN1_DIR/regtest/lightning-rpc ]; do
    sleep $POLL_INTERVAL
done
until [ -e $LN2_DIR/regtest/lightning-rpc ]; do
    sleep $POLL_INTERVAL
done

# Initialize wallet and get ourselves some money
function mine_blocks() {
    PEG_IN_ADDR="$($BTC_CLIENT getnewaddress)"
    $BTC_CLIENT generatetoaddress $1 $PEG_IN_ADDR
}
mine_blocks 101

# Open channel
LN_ADDR="$($LN1 newaddr | jq -r '.bech32')"
$BTC_CLIENT sendtoaddress $LN_ADDR 1
mine_blocks 10
export LN2_PUB_KEY="$($LN2 getinfo | jq -r '.id')"
export LN1_PUB_KEY="$($LN1 getinfo | jq -r '.id')"
$LN1 connect $LN2_PUB_KEY@127.0.0.1:9001
until $LN1 -k fundchannel id=$LN2_PUB_KEY amount=0.1btc push_msat=5000000000; do sleep $POLL_INTERVAL; done
mine_blocks 10
until [[ $($LN1 listpeers | jq -r ".peers[] | select(.id == \"$LN2_PUB_KEY\") | .channels[0].state") = "CHANNELD_NORMAL" ]]; do sleep $POLL_INTERVAL; done