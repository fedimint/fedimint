#!/usr/bin/env bash

POLL_INTERVAL=1
CONFIRMATION_TIME=10

# Fail instantly if anything goes wrong and log executed commands
set -euxo pipefail

# Clean up before exit
function cleanup {
  pkill server
  pkill ln_gateway
  pkill lightningd
  pkill bitcoind
}
trap cleanup EXIT

SRC_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"

# Define temporary directories to not overwrite manually created config if run locally
TMP_DIR="$(mktemp -d)"
echo "Working in $TMP_DIR"
LN1_DIR="$TMP_DIR/ln1"
mkdir $LN1_DIR
LN2_DIR="$TMP_DIR/ln2"
mkdir $LN2_DIR
BTC_DIR="$TMP_DIR/btc"
mkdir $BTC_DIR
CFG_DIR="$TMP_DIR/cfg"
mkdir $CFG_DIR

# Build all executables
cd $SRC_DIR
cargo build --release
BIN_DIR="$SRC_DIR/target/release"

# Start bitcoind and wait for it to become ready
bitcoind -regtest -fallbackfee=0.0004 -txindex -server -rpcuser=bitcoin -rpcpassword=bitcoin -datadir=$BTC_DIR &
BTC_CLIENT="bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin"
until [ "$($BTC_CLIENT getblockchaininfo | jq -r '.chain')" == "regtest" ]; do
  sleep $POLL_INTERVAL
done

# Create federation config (required by gateway plugin)
$BIN_DIR/configgen $CFG_DIR federation 4 4000 5000 1000 10000 100000 1000000 10000000

# Start lightning nodes. Lightning gateway is run as core-lightning plugin.
lightningd --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=$LN1_DIR \
    --addr=127.0.0.1:9000 --plugin=$BIN_DIR/ln_gateway --minimint-cfg=$CFG_DIR &
lightningd --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=$LN2_DIR \
    --addr=127.0.0.1:9001 &
until [ -e $LN1_DIR/regtest/lightning-rpc ]; do
    sleep $POLL_INTERVAL
done
until [ -e $LN2_DIR/regtest/lightning-rpc ]; do
    sleep $POLL_INTERVAL
done
LN1="lightning-cli --network regtest --lightning-dir=$LN1_DIR"
LN2="lightning-cli --network regtest --lightning-dir=$LN2_DIR"

# Run the Rust integration tests against the real Bitcoin / Lightning services
export MINIMINT_TEST_REAL=1
export MINIMINT_TEST_DIR=$TMP_DIR
cargo test -p minimint-tests -- --test-threads=1

# Initialize wallet and get ourselves some money
function mine_blocks() {
    PEG_IN_ADDR="$($BTC_CLIENT getnewaddress)"
    $BTC_CLIENT generatetoaddress $1 $PEG_IN_ADDR
}
mine_blocks 120

# Open channel
LN_ADDR="$($LN1 newaddr | jq -r '.bech32')"
$BTC_CLIENT sendtoaddress $LN_ADDR 1
mine_blocks 10
LN2_PUB_KEY="$($LN2 getinfo | jq -r '.id')"
$LN1 connect $LN2_PUB_KEY@127.0.0.1:9001
until $LN1 fundchannel $LN2_PUB_KEY 0.01btc; do sleep $POLL_INTERVAL; done
mine_blocks 10

# FIXME: make db path configurable to avoid cd-ing here
# Start the federation members inside the temporary directory
cd $TMP_DIR
for ((ID=0; ID<4; ID++)); do
  echo "starting mint $ID"
  ($BIN_DIR/server $CFG_DIR/server-$ID.json 2>&1 | sed -e "s/^/mint $ID: /" ) &
done

# Create client config
$BIN_DIR/configgen $CFG_DIR client 127.0.0.1:8080
MINT_CLIENT="$BIN_DIR/mint-client-cli $CFG_DIR"

function await_block_sync() {
  EXPECTED_BLOCK_HEIGHT="$(( $($BTC_CLIENT getblockchaininfo | jq -r '.blocks') - $CONFIRMATION_TIME ))"
  for ((ID=0; ID<4; ID++)); do
    MINT_API_URL="http://127.0.0.1:500$ID"
    until [ "$(curl $MINT_API_URL/wallet/block_height)" == "$EXPECTED_BLOCK_HEIGHT" ]; do
      sleep $POLL_INTERVAL
    done
  done
}
await_block_sync

#### BEGIN TESTS ####
# peg in
PEG_IN_ADDR="$($MINT_CLIENT peg-in-address)"
TX_ID="$($BTC_CLIENT sendtoaddress $PEG_IN_ADDR 0.00999999)"

# Confirm peg-in
mine_blocks 11
await_block_sync
TXOUT_PROOF="$($BTC_CLIENT gettxoutproof "[\"$TX_ID\"]")"
TRANSACTION="$($BTC_CLIENT getrawtransaction $TX_ID)"
$MINT_CLIENT peg-in "$TXOUT_PROOF" "$TRANSACTION"
$MINT_CLIENT fetch

# reissue
TOKENS=$($MINT_CLIENT spend 42000)
$MINT_CLIENT reissue $TOKENS
$MINT_CLIENT fetch

# peg out
PEG_OUT_ADDR="$($BTC_CLIENT getnewaddress)"
$MINT_CLIENT peg-out $PEG_OUT_ADDR 500
sleep 5 # wait for tx to be included
mine_blocks 120
await_block_sync
sleep 15
mine_blocks 10
RECEIVED=$($BTC_CLIENT getreceivedbyaddress $PEG_OUT_ADDR)
[[ "$RECEIVED" = "0.00000500" ]]

# outgoing lightning
INVOICE="$($LN2 invoice 100000000 test test 1m | jq -r '.bolt11')"
$MINT_CLIENT ln-pay $INVOICE
INVOICE_RESULT="$($LN2 waitinvoice test)"
INVOICE_STATUS="$(echo $INVOICE_RESULT | jq -r '.status')"
[[ "$INVOICE_STATUS" = "paid" ]]

# incoming lightning
# sleep 5 # wait for pay to settle (???)
INVOICE="$($MINT_CLIENT ln-invoice 10000 'integration test')"
RESULT=$($LN2 pay $INVOICE)
echo $RESULT

# TODO: fetch balances and check they match