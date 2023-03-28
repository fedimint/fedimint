#!/usr/bin/env bash
# Runs a CLI-based integration test

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

export PEG_IN_AMOUNT=10000
source ./scripts/setup-tests.sh

# Test config en/decryption tool
export FM_PASSWORD=pass0
$FM_DISTRIBUTEDGEN config-decrypt --in-file $FM_CFG_DIR/server-0/private.encrypt --out-file $FM_CFG_DIR/server-0/config-plaintext.json
export FM_PASSWORD=pass-foo
$FM_DISTRIBUTEDGEN config-encrypt --in-file $FM_CFG_DIR/server-0/config-plaintext.json --out-file $FM_CFG_DIR/server-0/config-2
$FM_DISTRIBUTEDGEN config-decrypt --in-file $FM_CFG_DIR/server-0/config-2 --out-file $FM_CFG_DIR/server-0/config-plaintext-2.json
cmp --silent $FM_CFG_DIR/server-0/config-plaintext.json $FM_CFG_DIR/server-0/config-plaintext-2.json

./scripts/pegin.sh # peg in user

export PEG_IN_AMOUNT=99999
start_gateways
./scripts/pegin.sh $PEG_IN_AMOUNT 1 # peg in gateway

#### BEGIN TESTS ####

# test the fetching of client configs
CONNECT_STRING=$(cat $FM_CFG_DIR/client-connect)
rm $FM_CFG_DIR/client.json
$FM_MINT_CLIENT join-federation "$CONNECT_STRING"

FED_ID="$(get_federation_id)"
[[ "$($FM_MINT_CLIENT decode-connect-info "$CONNECT_STRING" | jq -e -r '.id')" = "${FED_ID}" ]]
# Number required for one honest is ceil(($FM_FED_SIZE-1)/3+1)
ONE_HONEST=2
ONE_HONEST_URLS=$(cat $FM_CFG_DIR/client.json | jq --argjson one_honest $ONE_HONEST -e -r '.api_endpoints | to_entries[:$one_honest] | map(.value.url) | join(",")')
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
$FM_MINT_CLIENT peg-out $PEG_OUT_ADDR 500
until [ "$($FM_BTC_CLIENT getreceivedbyaddress $PEG_OUT_ADDR 0)" == "0.00000500" ]; do
  sleep $FM_POLL_INTERVAL
done
mine_blocks 10
RECEIVED=$($FM_BTC_CLIENT getreceivedbyaddress $PEG_OUT_ADDR)
[[ "$RECEIVED" = "0.00000500" ]]

# lightning tests
await_lightning_node_block_processing

# CLN gateway tests
use_cln_gw

# OUTGOING: fedimint-cli pays LND via CLN gateway
ADD_INVOICE="$($FM_LNCLI addinvoice --amt_msat 100000)"
INVOICE="$(echo $ADD_INVOICE| jq -e -r '.payment_request')"
PAYMENT_HASH="$(echo $ADD_INVOICE| jq -e -r '.r_hash')"
$FM_MINT_CLIENT ln-pay $INVOICE
# Check that ln-gateway has received the ecash notes from the user payment
# 100,000 sats + 100 sats without processing fee
# LN_GATEWAY_BALANCE="$($FM_GATEWAY_CLI balance $FED_ID | jq -e -r '.balance_msat')"
# [[ "$LN_GATEWAY_BALANCE" = "100100000" ]]
INVOICE_STATUS="$($FM_LNCLI lookupinvoice $PAYMENT_HASH | jq -e -r '.state')"
[[ "$INVOICE_STATUS" = "SETTLED" ]]

# INCOMING: fedimint-cli receives from LND via CLN gateway
INVOICE="$($FM_MINT_CLIENT ln-invoice '100000msat' 'incoming-over-lnd-gw' | jq -e -r '.invoice')"
PAYMENT="$($FM_LNCLI payinvoice --force $INVOICE)"
PAYMENT_HASH="$(echo $PAYMENT | awk '{ print $30 }')"
LND_PAYMENTS="$($FM_LNCLI listpayments --include_incomplete)"
PAYMENT_STATUS="$(echo $LND_PAYMENTS | jq -e -r '.payments[] | select(.payment_hash == "'$PAYMENT_HASH'") | .status')"
[[ "$PAYMENT_STATUS" = "SUCCEEDED" ]]

# LND gateway tests
use_lnd_gw

# OUTGOING: fedimint-cli pays CLN via LND gateaway
INVOICE="$($FM_LIGHTNING_CLI invoice 100000 lnd-gw-to-cln test 1m | jq -e -r '.bolt11')"
await_lightning_node_block_processing
$FM_MINT_CLIENT ln-pay $INVOICE
FED_ID="$(get_federation_id)"
INVOICE_RESULT="$($FM_LIGHTNING_CLI waitinvoice lnd-gw-to-cln)"
INVOICE_STATUS="$(echo $INVOICE_RESULT | jq -e -r '.status')"
[[ "$INVOICE_STATUS" = "paid" ]]

# INCOMING: fedimint-cli receives from CLN via LND gateway
INVOICE="$($FM_MINT_CLIENT ln-invoice '100000msat' 'integration test' | jq -e -r '.invoice')"
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
