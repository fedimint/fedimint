#!/usr/bin/env bash
# Calls the CLI to peg user client into the federation
echo "Run with 'source ./scripts/pegin.sh [amount] [use_gateway]"

set -euo pipefail

function mine_blocks() {
    PEG_IN_ADDR="$($FM_BTC_CLIENT getnewaddress)"
    $FM_BTC_CLIENT generatetoaddress $1 $PEG_IN_ADDR
}

function await_fedimint_block_sync() {
  BLOCKS="$($FM_BTC_CLIENT getblockchaininfo | jq -e -r '.blocks')"
  FINALITY_DELAY=10
  AWAIT="$((BLOCKS - FINALITY_DELAY))"
  echo "await_fedimint_block_sync $AWAIT"
  $FM_MINT_CLIENT wait-block-height "$AWAIT"
}

function sat_to_btc() {
    echo "scale=8; $1/100000000" | bc | awk '{printf "%.8f\n", $0}'
}

#caller should call mine_blocks() after this
function send_bitcoin() {
    local RECV_ADDRESS
    RECV_ADDRESS=$1
    local SEND_AMT
    SEND_AMT=$2

    local TX_ID
    TX_ID="$($FM_BTC_CLIENT sendtoaddress $RECV_ADDRESS "$(sat_to_btc $SEND_AMT)")"
    echo $TX_ID
}

function get_txout_proof() {
    local TX_ID
    TX_ID=$1

    local TXOUT_PROOF
    TXOUT_PROOF="$($FM_BTC_CLIENT gettxoutproof "[\"$TX_ID\"]")"
    echo $TXOUT_PROOF
}

function get_raw_transaction() {
    local TX_ID
    TX_ID=$1

    local TRANSACTION
    TRANSACTION="$($FM_BTC_CLIENT getrawtransaction $TX_ID)"
    echo $TRANSACTION
}

function get_federation_id() {
    cat $FM_DATA_DIR/client.json | jq -e -r '.federation_id'
}

# Bitcoin amount in satoshi

PEG_IN_AMOUNT=${PEG_IN_AMOUNT:-$1}
USE_GATEWAY=${2:-0}
GATEWAY_TYPE=${3:-"CLN"}

if [ "$GATEWAY_TYPE" == "CLN" ]; then GATEWAY_CLI=$FM_GWCLI_CLN; else GATEWAY_CLI=$FM_GWCLI_LND; fi

FINALITY_DELAY=10
echo "Pegging in $PEG_IN_AMOUNT with confirmation in $FINALITY_DELAY blocks"

FED_ID="$(get_federation_id)"

# get a peg-in address from either the gateway or the client
if [ "$USE_GATEWAY" == 1 ]; then ADDR="$($GATEWAY_CLI address --federation-id "$FED_ID" | jq -e -r '.address')"; else ADDR="$($FM_MINT_CLIENT peg-in-address | jq -e -r '.address')"; fi
# send bitcoin to that address and save the txid
TX_ID=$(send_bitcoin $ADDR $PEG_IN_AMOUNT)
# wait for confirmation and wait for the fed to sync
mine_blocks 11
await_fedimint_block_sync
#get the txoutproof and the raw transaction from the txid
TXOUT_PROOF=$(get_txout_proof $TX_ID)
TRANSACTION=$(get_raw_transaction $TX_ID)

# With these proofs we can instruct the client to start the peg-in process. Our client will add the tweak used to derive
# the peg-in address to the request so that the federation can claim the funds later.
if [ "$USE_GATEWAY" == 1 ]; then $GATEWAY_CLI deposit --federation-id "$FED_ID" --txout-proof "$TXOUT_PROOF" --transaction "$TRANSACTION" && echo "Pegged in to federation with id: $FED_ID"; else $FM_MINT_CLIENT peg-in --txout-proof "$TXOUT_PROOF" --transaction "$TRANSACTION"; fi

# Since the process is asynchronous have to come back to fetch the result later. We choose to do this right away and
# just block till we get our notes.
$FM_MINT_CLIENT fetch
