#!/usr/bin/env bash

POLL_INTERVAL=1
CONFIRMATION_TIME=10
FED_SIZE=${1:-4}

# Fail instantly if anything goes wrong and log executed commands
set -e

# Clean up before exit
function cleanup {
  pkill server
  pkill ln_gateway
}
trap cleanup EXIT

SRC_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
export RUST_LOG=error,ln_gateway=off

# Define temporary directories to not overwrite manually created config if run locally
TMP_DIR="$SRC_DIR/it"
echo "Working in $TMP_DIR"
LN1_DIR="$TMP_DIR/ln1"
LN2_DIR="$TMP_DIR/ln2"
CFG_DIR="$TMP_DIR/cfg"
rm -rf $CFG_DIR
mkdir $CFG_DIR

# Build all executables
cd $SRC_DIR
cargo build --release
BIN_DIR="$SRC_DIR/target/release"

# Assumes bitcoin and lightning are started
BTC_CLIENT="bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin"
LN1="lightning-cli --network regtest --lightning-dir=$LN1_DIR"
LN2="lightning-cli --network regtest --lightning-dir=$LN2_DIR"

# Generate federation, gateway and client config
$BIN_DIR/configgen -- $CFG_DIR $FED_SIZE 4000 5000 1000 10000 100000 1000000 10000000
LN1_PUB_KEY="$($LN1 getinfo | jq -r '.id')"
$BIN_DIR/gw_configgen -- $CFG_DIR "$LN1_DIR/regtest/lightning-rpc" $LN1_PUB_KEY

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
until $LN1 fundchannel $LN2_PUB_KEY 0.1btc; do sleep $POLL_INTERVAL; done
mine_blocks 10

# FIXME: make db path configurable to avoid cd-ing here
# Start the federation members inside the temporary directory
cd $TMP_DIR
echo "CONFIG $CFG_DIR"
for ((ID=0; ID<$FED_SIZE; ID++)); do
  echo "starting mint $ID"
  ($BIN_DIR/server $CFG_DIR/server-$ID.json 2>&1 | sed -e "s/^/mint $ID: /" ) &
done
MINT_CLIENT="$BIN_DIR/mint-client-cli $CFG_DIR"

function await_block_sync() {
  EXPECTED_BLOCK_HEIGHT="$(( $($BTC_CLIENT getblockchaininfo | jq -r '.blocks') - $CONFIRMATION_TIME ))"
  for ((ID=0; ID<$FED_SIZE; ID++)); do
    MINT_API_URL="http://127.0.0.1:500$ID"
    until [ "$(curl $MINT_API_URL/wallet/block_height)" == "$EXPECTED_BLOCK_HEIGHT" ]; do
      sleep $POLL_INTERVAL
    done
  done
}
await_block_sync

# Start LN gateway
$BIN_DIR/ln_gateway $CFG_DIR &

#### BEGIN TESTS ####
# peg in
PEG_IN_ADDR="$($MINT_CLIENT peg-in-address)"
TX_ID="$($BTC_CLIENT sendtoaddress $PEG_IN_ADDR  0.00099999)"

# Confirm peg-in
mine_blocks 11
await_block_sync
TXOUT_PROOF="$($BTC_CLIENT gettxoutproof "[\"$TX_ID\"]")"
TRANSACTION="$($BTC_CLIENT getrawtransaction $TX_ID)"
$MINT_CLIENT peg-in "$TXOUT_PROOF" "$TRANSACTION"
$MINT_CLIENT fetch

# reissue
time for i in {1..10}
do
  echo "REISSUE $i"
  TOKENS=$($MINT_CLIENT spend 1000)
  $MINT_CLIENT reissue $TOKENS
  $MINT_CLIENT fetch
done

## outgoing lightning
time for i in {1..10}
do
  echo "PAY INVOICE $i"
  LABEL=test$RANDOM$RANDOM
  INVOICE="$($LN2 invoice 100000 $LABEL $LABEL 1m | jq -r '.bolt11')"
  $MINT_CLIENT ln-pay $INVOICE
  INVOICE_RESULT="$($LN2 waitinvoice $LABEL)"
  INVOICE_STATUS="$(echo $INVOICE_RESULT | jq -r '.status')"
  echo "RESULT $INVOICE_STATUS"
  [[ "$INVOICE_STATUS" = "paid" ]]
done
