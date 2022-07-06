#!/usr/bin/env bash
# Starts Bitcoin and 2 LN nodes, opening a channel between the LN nodes

function kill_minimint_processes {
  while read pid; do
    kill $pid || true
  done <$PID_FILE
  rm $PID_FILE
}
trap kill_minimint_processes EXIT

# Define temporary directories to not overwrite manually created config if run locally
export MINIMINT_TEST_DIR="$(mktemp -d)"
export PID_FILE=".pid"
POLL_INTERVAL=1
echo "Working in $MINIMINT_TEST_DIR"
export LN1_DIR="$MINIMINT_TEST_DIR/ln1"
mkdir $LN1_DIR
export LN2_DIR="$MINIMINT_TEST_DIR/ln2"
mkdir $LN2_DIR
export BTC_DIR="$MINIMINT_TEST_DIR/bitcoin"
mkdir $BTC_DIR

# Start bitcoind and wait for it to become ready
bitcoind -regtest -fallbackfee=0.0004 -txindex -server -rpcuser=bitcoin -rpcpassword=bitcoin -datadir=$BTC_DIR &
echo $! >> $PID_FILE
BTC_CLIENT="bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin"
until [ "$($BTC_CLIENT getblockchaininfo | jq -r '.chain')" == "regtest" ]; do
  sleep $POLL_INTERVAL
done
$BTC_CLIENT createwallet ""

# Start lightning nodes
lightningd --dev-fast-gossip --dev-bitcoind-poll=1 --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=$LN1_DIR --addr=127.0.0.1:9000 &
echo $! >> $PID_FILE
lightningd --dev-fast-gossip --dev-bitcoind-poll=1 --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=$LN2_DIR --addr=127.0.0.1:9001 &
echo $! >> $PID_FILE
until [ -e $LN1_DIR/regtest/lightning-rpc ]; do
    sleep $POLL_INTERVAL
done
until [ -e $LN2_DIR/regtest/lightning-rpc ]; do
    sleep $POLL_INTERVAL
done
export LN1="lightning-cli --network regtest --lightning-dir=$LN1_DIR"
export LN2="lightning-cli --network regtest --lightning-dir=$LN2_DIR"

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
until $LN1 fundchannel $LN2_PUB_KEY 0.1btc; do sleep $POLL_INTERVAL; done
mine_blocks 10
until [[ $($LN1 listpeers | jq -r ".peers[] | select(.id == \"$LN2_PUB_KEY\") | .channels[0].state") = "CHANNELD_NORMAL" ]]; do sleep $POLL_INTERVAL; done

alias ln1="\$LN1"
alias ln2="\$LN1"
alias btc_client="\$BTC_CLIENT"