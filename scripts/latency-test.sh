#!/usr/bin/env bash
# Runs a test to determine the latency of certain user actions

set -eu
FM_FED_SIZE=${1:-4}
ITERATIONS=${2:-10}
if [ -z "${RUST_LOG:-}" ]; then
  export RUST_LOG=error
fi
export PEG_IN_AMOUNT=10000000

source ./scripts/setup-tests.sh $FM_FED_SIZE
./scripts/start-fed.sh
./scripts/pegin.sh
start_gatewayd

#### BEGIN TESTS ####
echo "Running with fed size $FM_FED_SIZE"

# reissue
time1=$(date +%s.%N)
for i in $( seq 1 $ITERATIONS )
do
  echo "REISSUE $i"
  NOTES=$($FM_MINT_CLIENT spend 50000 | jq -e -r '.note')
  $FM_MINT_CLIENT reissue $NOTES
  $FM_MINT_CLIENT fetch
done
time2=$(date +%s.%N)

await_gateway_registered

## outgoing lightning
for i in $( seq 1 $ITERATIONS )
do
  echo "LN SEND $i"
  ADD_INVOICE="$($FM_LNCLI addinvoice --amt_msat 100000)"
  INVOICE="$(echo $ADD_INVOICE| jq -e -r '.payment_request')"
  PAYMENT_HASH="$(echo $ADD_INVOICE| jq -e -r '.r_hash')"
  $FM_MINT_CLIENT ln-pay $INVOICE
  INVOICE_STATUS="$($FM_LNCLI lookupinvoice $PAYMENT_HASH | jq -e -r '.state')"
  [[ "$INVOICE_STATUS" = "SETTLED" ]]
done
time3=$(date +%s.%N)

## incoming lightning
for i in $( seq 1 $ITERATIONS )
do
  echo "LN RECEIVE $i"
  INVOICE="$($FM_MINT_CLIENT ln-invoice '100000msat' 'incoming-over-lnd-gw' | jq -e -r '.invoice')"
  PAYMENT="$($FM_LNCLI payinvoice --force $INVOICE)"
  PAYMENT_HASH="$(echo $PAYMENT | awk '{ print $30 }')"
  LND_PAYMENTS="$($FM_LNCLI listpayments --include_incomplete)"
  PAYMENT_STATUS="$(echo $LND_PAYMENTS | jq -e -r '.payments[] | select(.payment_hash == "'$PAYMENT_HASH'") | .status')"
  [[ "$PAYMENT_STATUS" = "SUCCEEDED" ]]
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
