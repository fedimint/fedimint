#!/usr/bin/env bash
# Runs a CLI-based integration test

set -euxo pipefail
export RUST_LOG=info
export PEG_IN_AMOUNT=0.00099999

source ./scripts/build.sh
source ./scripts/setup-tests.sh
./scripts/start-fed.sh
./scripts/start-gateway.sh
source ./scripts/pegin.sh

#### BEGIN TESTS ####

# reissue
TOKENS=$($MINT_CLIENT spend 42000)
$MINT_CLIENT reissue $TOKENS
$MINT_CLIENT fetch

# peg out
PEG_OUT_ADDR="$($BTC_CLIENT getnewaddress)"
$MINT_CLIENT peg-out $PEG_OUT_ADDR 500
sleep 5 # FIXME wait for tx to be included
mine_blocks 120
await_block_sync
until [ "$($BTC_CLIENT getreceivedbyaddress $PEG_OUT_ADDR 0)" == "0.00000500" ]; do
  sleep $POLL_INTERVAL
done
mine_blocks 10
RECEIVED=$($BTC_CLIENT getreceivedbyaddress $PEG_OUT_ADDR)
[[ "$RECEIVED" = "0.00000500" ]]

# outgoing lightning
INVOICE="$($LN2 invoice 100000 test test 1m | jq -r '.bolt11')"
$MINT_CLIENT ln-pay $INVOICE
INVOICE_RESULT="$($LN2 waitinvoice test)"
INVOICE_STATUS="$(echo $INVOICE_RESULT | jq -r '.status')"
[[ "$INVOICE_STATUS" = "paid" ]]