#!/usr/bin/env bash
# Runs a test to determine the latency of certain user actions

set -eu
FED_SIZE=${1:-4}
export RUST_LOG=error,ln_gateway=off
export PEG_IN_AMOUNT=0.00099999

source ./scripts/build.sh $FED_SIZE
source ./scripts/setup-tests.sh
./scripts/start-fed.sh
./scripts/pegin.sh

#### BEGIN TESTS ####
echo "Running with fed size $FED_SIZE"

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
  echo "LN SEND $i"
  LABEL=test$RANDOM$RANDOM
  INVOICE="$($LN2 invoice 500000 $LABEL $LABEL 1m | jq -r '.bolt11')"
  $MINT_CLIENT ln-pay $INVOICE
  INVOICE_RESULT="$($LN2 waitinvoice $LABEL)"
  INVOICE_STATUS="$(echo $INVOICE_RESULT | jq -r '.status')"
  echo "RESULT $INVOICE_STATUS"
  [[ "$INVOICE_STATUS" = "paid" ]]
done

## incoming lightning
time for i in {1..10}
do
  echo "LN RECEIVE $i"
  INVOICE="$($MINT_CLIENT ln-invoice 500000 '$RANDOM')"
  INVOICE_RESULT=$($LN2 pay $INVOICE)
  INVOICE_STATUS="$(echo $INVOICE_RESULT | jq -r '.status')"
  echo "RESULT $INVOICE_STATUS"
  [[ "$INVOICE_STATUS" = "complete" ]]
done