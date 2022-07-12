#!/usr/bin/env bash
# Runs a test to determine the latency of certain user actions

set -eu
FED_SIZE=${1:-4}
ITERATIONS=${2:-5}
export RUST_LOG=error,ln_gateway=off
export PEG_IN_AMOUNT=0.00099999

source ./scripts/build.sh $FED_SIZE
source ./scripts/setup-tests.sh
./scripts/start-fed.sh
./scripts/pegin.sh

#### BEGIN TESTS ####
echo "Running with fed size $FED_SIZE"

# reissue
time1=$(date +%s.%N)
for i in $( seq 1 $ITERATIONS )
do
  echo "REISSUE $i"
  TOKENS=$($MINT_CLIENT spend 1000)
  $MINT_CLIENT reissue $TOKENS
  $MINT_CLIENT fetch
done
time2=$(date +%s.%N)

## outgoing lightning
for i in $( seq 1 $ITERATIONS )
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
time3=$(date +%s.%N)

## incoming lightning
for i in $( seq 1 $ITERATIONS )
do
  echo "LN RECEIVE $i"
  INVOICE="$($MINT_CLIENT ln-invoice 500000 '$RANDOM')"
  INVOICE_RESULT=$($LN2 pay $INVOICE)
  INVOICE_STATUS="$(echo $INVOICE_RESULT | jq -r '.status')"
  echo "RESULT $INVOICE_STATUS"
  [[ "$INVOICE_STATUS" = "complete" ]]
done
time4=$(date +%s.%N)

# TODO running outputs spurious error logs
REISSUE=$(echo "scale=3; ($time2 - $time1) / $ITERATIONS" | bc)
echo "AVG REISSUE TIME: $REISSUE seconds"
LN_SEND=$(echo "scale=3; ($time3 - $time2) / $ITERATIONS" | bc)
echo "AVG LN SEND TIME: $LN_SEND seconds"
LN_RECEIVE=$(echo "scale=3; ($time4 - $time3) / $ITERATIONS" | bc)
echo "AVG LN RECEIVE TIME: $LN_RECEIVE seconds"

# Assert that avg runtimes are under 5 sec
[[ $(echo "$REISSUE < 5" | bc -l) = 1 ]]
[[ $(echo "$LN_SEND < 5" | bc -l) = 1 ]]
[[ $(echo "$LN_RECEIVE < 5" | bc -l) = 1 ]]