#!/usr/bin/env bash

set -u

# Starts Bitcoin and 2 LN nodes, opening a channel between the LN nodes
POLL_INTERVAL=1

# Start bitcoind and wait for it to become ready
bitcoind -regtest -fallbackfee=0.0004 -txindex -server -rpcuser=bitcoin -rpcpassword=bitcoin -datadir=$FM_BTC_DIR &
echo $! >> $FM_PID_FILE

until [ "$($FM_BTC_CLIENT getblockchaininfo | jq -r '.chain')" == "regtest" ]; do
  sleep $POLL_INTERVAL
done
$FM_BTC_CLIENT createwallet ""

if [[ "$(lightningd --bitcoin-cli "$(which false)" --dev-no-plugin-checksum 2>&1 )" =~ .*"--dev-no-plugin-checksum: unrecognized option".* ]]; then
  LIGHTNING_FLAGS=""
else
  LIGHTNING_FLAGS="--dev-fast-gossip --dev-bitcoind-poll=1"
fi

# Start lightning nodes
lightningd $LIGHTNING_FLAGS --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=$FM_LN1_DIR --addr=127.0.0.1:9000 --plugin=$FM_BIN_DIR/ln_gateway --minimint-cfg=$FM_CFG_DIR &
echo $! >> $FM_PID_FILE
lightningd $LIGHTNING_FLAGS --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=$FM_LN2_DIR --addr=127.0.0.1:9001 &
echo $! >> $FM_PID_FILE
until [ -e $FM_LN1_DIR/regtest/lightning-rpc ]; do
    sleep $POLL_INTERVAL
done
until [ -e $FM_LN2_DIR/regtest/lightning-rpc ]; do
    sleep $POLL_INTERVAL
done

# Initialize wallet and get ourselves some money
function mine_blocks() {
    PEG_IN_ADDR="$($FM_BTC_CLIENT getnewaddress)"
    $FM_BTC_CLIENT generatetoaddress $1 $PEG_IN_ADDR
}
mine_blocks 101

# Open channel
LN_ADDR="$($FM_LN1 newaddr | jq -r '.bech32')"
$FM_BTC_CLIENT sendtoaddress $LN_ADDR 1
mine_blocks 10
export FM_LN2_PUB_KEY="$($FM_LN2 getinfo | jq -r '.id')"
export FM_LN1_PUB_KEY="$($FM_LN1 getinfo | jq -r '.id')"
$FM_LN1 connect $FM_LN2_PUB_KEY@127.0.0.1:9001
until $FM_LN1 -k fundchannel id=$FM_LN2_PUB_KEY amount=0.1btc push_msat=5000000000; do sleep $POLL_INTERVAL; done
mine_blocks 10
until [[ $($FM_LN1 listpeers | jq -r ".peers[] | select(.id == \"$FM_LN2_PUB_KEY\") | .channels[0].state") = "CHANNELD_NORMAL" ]]; do sleep $POLL_INTERVAL; done