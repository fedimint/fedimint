#!/usr/bin/env bash
# Runs a CLI-based integration test

set -euxo pipefail
export RUST_LOG="${RUST_LOG:-info}"

export PEG_IN_AMOUNT=10000
source ./scripts/setup-tests.sh

# Test config en/decryption tool
export FM_PASSWORD=pass0
$FM_DISTRIBUTEDGEN config-decrypt --in-file $FM_DATA_DIR/server-0/private.encrypt --out-file $FM_DATA_DIR/server-0/config-plaintext.json
export FM_PASSWORD=pass-foo
$FM_DISTRIBUTEDGEN config-encrypt --in-file $FM_DATA_DIR/server-0/config-plaintext.json --out-file $FM_DATA_DIR/server-0/config-2
$FM_DISTRIBUTEDGEN config-decrypt --in-file $FM_DATA_DIR/server-0/config-2 --out-file $FM_DATA_DIR/server-0/config-plaintext-2.json
cmp --silent $FM_DATA_DIR/server-0/config-plaintext.json $FM_DATA_DIR/server-0/config-plaintext-2.json

./scripts/pegin.sh # peg in user

export PEG_IN_AMOUNT=99999
start_gateways
./scripts/pegin.sh $PEG_IN_AMOUNT 1 # peg in gateway

#### BEGIN TESTS ####

# test the fetching of client configs
CONNECT_STRING=$(cat $FM_DATA_DIR/client-connect)
rm $FM_DATA_DIR/client.json
$FM_MINT_CLIENT join-federation "$CONNECT_STRING"

FED_ID="$(get_federation_id)"
[[ "$($FM_MINT_CLIENT decode-connect-info "$CONNECT_STRING" | jq -e -r '.id')" = "${FED_ID}" ]]
# Number required for one honest is ceil(($FM_FED_SIZE-1)/3+1)
ONE_HONEST=2
ONE_HONEST_URLS=$(cat $FM_DATA_DIR/client.json | jq --argjson one_honest $ONE_HONEST -e -r '.api_endpoints | to_entries[:$one_honest] | map(.value.url) | join(",")')
[[ "$($FM_MINT_CLIENT decode-connect-info "$CONNECT_STRING" | jq -e -r '.urls | join(",")')" = "$ONE_HONEST_URLS" ]]
[[ "$($FM_MINT_CLIENT encode-connect-info --urls $ONE_HONEST_URLS --id $FED_ID | jq -e -r '.connect_info')" = "$CONNECT_STRING" ]]

# reissue
NOTES=$($FM_MINT_CLIENT spend '42000msat' | jq -e -r '.note')
[[ $($FM_MINT_CLIENT info | jq -e -r '.total_amount') = "9958000" ]]
$FM_MINT_CLIENT validate $NOTES
$FM_MINT_CLIENT reissue $NOTES
$FM_MINT_CLIENT fetch

# peg out
PEG_OUT_ADDR="$($FM_BTC_CLIENT getnewaddress)"
$FM_MINT_CLIENT peg-out --address $PEG_OUT_ADDR --amount 500sat
until [ "$($FM_BTC_CLIENT getreceivedbyaddress $PEG_OUT_ADDR 0)" == "0.00000500" ]; do
  sleep $FM_POLL_INTERVAL
done
mine_blocks 10
RECEIVED=$($FM_BTC_CLIENT getreceivedbyaddress $PEG_OUT_ADDR)
if [[ "$RECEIVED" != "0.00000500" ]]; then
  echo "Peg-out address received $RECEIVED, expected 0.00000500"
  exit 1
fi

# lightning tests
await_lightning_node_block_processing

# CLN gateway tests
use_cln_gw

# OUTGOING: fedimint-cli pays LND via CLN gateway
INITIAL_CLIENT_BALANCE="$($FM_MINT_CLIENT info | jq -e -r '.total_amount')"
INITIAL_GATEWAY_BALANCE="$($FM_GWCLI_CLN balance $FED_ID | jq -e -r '.balance_msat')"
ADD_INVOICE="$($FM_LNCLI addinvoice --amt_msat 100000)"
INVOICE="$(echo $ADD_INVOICE| jq -e -r '.payment_request')"
PAYMENT_HASH="$(echo $ADD_INVOICE| jq -e -r '.r_hash')"
$FM_MINT_CLIENT ln-pay $INVOICE

INVOICE_STATUS="$($FM_LNCLI lookupinvoice $PAYMENT_HASH | jq -e -r '.state')"
[[ "$INVOICE_STATUS" = "SETTLED" ]]

# Assert balances changed by 100000 msat (amount sent) + 1000 msat (fee)
FINAL_CLIENT_BALANCE="$($FM_MINT_CLIENT info | jq -e -r '.total_amount')"
FINAL_GATEWAY_BALANCE="$($FM_GWCLI_CLN balance $FED_ID | jq -e -r '.balance_msat')"
if [[ "$(($INITIAL_CLIENT_BALANCE - $FINAL_CLIENT_BALANCE))" != 101000 ]]; then
  echo "Client balance changed by $(($INITIAL_CLIENT_BALANCE - $FINAL_CLIENT_BALANCE)), expected 101000"
  exit 1
fi
if [[ "$(($FINAL_GATEWAY_BALANCE - $INITIAL_GATEWAY_BALANCE))" != 101000 ]]; then
  echo "Gateway balance changed by $(($FINAL_GATEWAY_BALANCE - $INITIAL_GATEWAY_BALANCE)), expected 101000"
  exit 1
fi

# INCOMING: fedimint-cli receives from LND via CLN gateway
INVOICE="$($FM_MINT_CLIENT ln-invoice --amount '100000msat' --description 'incoming-over-lnd-gw' | jq -e -r '.invoice')"
PAYMENT="$($FM_LNCLI payinvoice --force $INVOICE)"
PAYMENT_HASH="$(echo $PAYMENT | awk '{ print $30 }')"
LND_PAYMENTS="$($FM_LNCLI listpayments --include_incomplete)"
PAYMENT_STATUS="$(echo $LND_PAYMENTS | jq -e -r '.payments[] | select(.payment_hash == "'$PAYMENT_HASH'") | .status')"
[[ "$PAYMENT_STATUS" = "SUCCEEDED" ]]

# LND gateway tests
use_lnd_gw

# OUTGOING: fedimint-cli pays CLN via LND gateaway
INITIAL_CLIENT_BALANCE="$($FM_MINT_CLIENT info | jq -e -r '.total_amount')"
INITIAL_GATEWAY_BALANCE="$($FM_GWCLI_LND balance $FED_ID | jq -e -r '.balance_msat')"
INVOICE="$($FM_LIGHTNING_CLI invoice 100000 lnd-gw-to-cln test 1m | jq -e -r '.bolt11')"
await_lightning_node_block_processing
$FM_MINT_CLIENT ln-pay $INVOICE
FED_ID="$(get_federation_id)"

INVOICE_RESULT="$($FM_LIGHTNING_CLI waitinvoice lnd-gw-to-cln)"
INVOICE_STATUS="$(echo $INVOICE_RESULT | jq -e -r '.status')"
[[ "$INVOICE_STATUS" = "paid" ]]

# Assert balances changed by 100000 msat (amount sent) + 1000 msat (fee)
FINAL_CLIENT_BALANCE="$($FM_MINT_CLIENT info | jq -e -r '.total_amount')"
FINAL_GATEWAY_BALANCE="$($FM_GWCLI_LND balance $FED_ID | jq -e -r '.balance_msat')"
if [[ "$(($INITIAL_CLIENT_BALANCE - $FINAL_CLIENT_BALANCE))" != 101000 ]]; then
  echo "Client balance changed by $(($INITIAL_CLIENT_BALANCE - $FINAL_CLIENT_BALANCE)), expected 101000"
  exit 1
fi
if [[ "$(($FINAL_GATEWAY_BALANCE - $INITIAL_GATEWAY_BALANCE))" != 101000 ]]; then
  echo "Gateway balance changed by $(($FINAL_GATEWAY_BALANCE - $INITIAL_GATEWAY_BALANCE)), expected 101000"
  exit 1
fi

# INCOMING: fedimint-cli receives from CLN via LND gateway
INVOICE="$($FM_MINT_CLIENT ln-invoice --amount '100000msat' --description 'integration test' | jq -e -r '.invoice')"
INVOICE_RESULT=$($FM_LIGHTNING_CLI pay $INVOICE)
INVOICE_STATUS="$(echo $INVOICE_RESULT | jq -e -r '.status')"
[[ "$INVOICE_STATUS" = "complete" ]]

# Test that LND and CLN can still send directly to each other

# LND can pay CLN directly
INVOICE="$($FM_LIGHTNING_CLI invoice 42000 test test 1m | jq -e -r '.bolt11')"
$FM_LNCLI payinvoice --force "$INVOICE"
INVOICE_STATUS="$($FM_LIGHTNING_CLI waitinvoice test | jq -e -r '.status')"
[[ "$INVOICE_STATUS" = "paid" ]]

# CLN can pay LND directly
ADD_INVOICE="$($FM_LNCLI addinvoice --amt_msat 42000)"
INVOICE="$(echo $ADD_INVOICE| jq -e -r '.payment_request')"
PAYMENT_HASH="$(echo $ADD_INVOICE| jq -e -r '.r_hash')"
$FM_LIGHTNING_CLI pay "$INVOICE"
INVOICE_STATUS="$($FM_LNCLI lookupinvoice $PAYMENT_HASH | jq -e -r '.state')"
[[ "$INVOICE_STATUS" = "SETTLED" ]]

echo "fm success: cli-test"
