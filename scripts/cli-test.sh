#!/usr/bin/env bash
# Runs a CLI-based integration test

set -euxo pipefail
export RUST_LOG=info

export PEG_IN_AMOUNT=10000
source ./scripts/setup-tests.sh

# Test config en/decryption tool
export FM_PASSWORD=pass0
$FM_DISTRIBUTEDGEN config-decrypt --in-file $FM_CFG_DIR/server-0/private.encrypt --out-file $FM_CFG_DIR/server-0/config-plaintext.json
export FM_PASSWORD=pass-foo
$FM_DISTRIBUTEDGEN config-encrypt --in-file $FM_CFG_DIR/server-0/config-plaintext.json --out-file $FM_CFG_DIR/server-0/config-2
$FM_DISTRIBUTEDGEN config-decrypt --in-file $FM_CFG_DIR/server-0/config-2 --out-file $FM_CFG_DIR/server-0/config-plaintext-2.json
cmp --silent $FM_CFG_DIR/server-0/config-plaintext.json $FM_CFG_DIR/server-0/config-plaintext-2.json

./scripts/start-fed.sh
./scripts/pegin.sh # peg in user

export PEG_IN_AMOUNT=99999
start_gateway
./scripts/pegin.sh $PEG_IN_AMOUNT 1 # peg in gateway

#### BEGIN TESTS ####

# test the fetching of client configs
CONNECT_STRING=$(cat $FM_CFG_DIR/client-connect.json)
rm $FM_CFG_DIR/client.json
$FM_MINT_CLIENT join-federation "$CONNECT_STRING"

# reissue
TOKENS=$($FM_MINT_CLIENT spend '42000msat' | jq -e -r '.token')
[[ $($FM_MINT_CLIENT info | jq -e -r '.total_amount') = "9958000" ]]
$FM_MINT_CLIENT validate $TOKENS
$FM_MINT_CLIENT reissue $TOKENS
$FM_MINT_CLIENT fetch

# peg out
PEG_OUT_ADDR="$($FM_BTC_CLIENT getnewaddress)"
$FM_MINT_CLIENT peg-out $PEG_OUT_ADDR 500
sleep 5 # FIXME wait for tx to be included
await_fedimint_block_sync
until [ "$($FM_BTC_CLIENT getreceivedbyaddress $PEG_OUT_ADDR 0)" == "0.00000500" ]; do
  sleep $POLL_INTERVAL
done
mine_blocks 10
RECEIVED=$($FM_BTC_CLIENT getreceivedbyaddress $PEG_OUT_ADDR)
[[ "$RECEIVED" = "0.00000500" ]]

# outgoing lightning
INVOICE="$($FM_LN2 invoice 100000 test test 1m | jq -e -r '.bolt11')"
await_cln_block_processing
$FM_MINT_CLIENT ln-pay $INVOICE
# Check that ln-gateway has received the ecash notes from the user payment
# 100,000 sats + 100 sats without processing fee
FED_ID="$(get_federation_id)"
LN_GATEWAY_BALANCE="$($FM_GATEWAY_CLI balance $FED_ID | jq -e -r '.balance_msat')"
[[ "$LN_GATEWAY_BALANCE" = "100100000" ]]
INVOICE_RESULT="$($FM_LN2 waitinvoice test)"
INVOICE_STATUS="$(echo $INVOICE_RESULT | jq -e -r '.status')"
[[ "$INVOICE_STATUS" = "paid" ]]

# test that LN1 can still receive directly even though running the plugin
INVOICE="$($FM_LN1 invoice 42000 test test 1m | jq -e -r '.bolt11')"
$FM_LN2 pay "$INVOICE"
INVOICE_STATUS="$($FM_LN1 waitinvoice test | jq -e -r '.status')"
[[ "$INVOICE_STATUS" = "paid" ]]

# incoming lightning
INVOICE="$($FM_MINT_CLIENT ln-invoice '100000msat' 'integration test' | jq -e -r '.invoice')"
INVOICE_RESULT=$($FM_LN2 pay $INVOICE)
INVOICE_STATUS="$(echo $INVOICE_RESULT | jq -e -r '.status')"
[[ "$INVOICE_STATUS" = "complete" ]]
