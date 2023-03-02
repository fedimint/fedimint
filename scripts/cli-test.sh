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
await_cln_block_processing
start_gatewayd

./scripts/pegin.sh $PEG_IN_AMOUNT CLN # peg in CLN gateway
./scripts/pegin.sh $PEG_IN_AMOUNT LND # peg in LND gateway

#### BEGIN TESTS ####

# test the fetching of client configs
CONNECT_STRING=$(cat $FM_CFG_DIR/client-connect)
rm $FM_CFG_DIR/client.json
$FM_MINT_CLIENT join-federation "$CONNECT_STRING"

FED_ID="$(get_federation_id)"
[[ "$($FM_MINT_CLIENT decode-connect-info "$CONNECT_STRING" | jq -e -r '.id')" = "${FED_ID}" ]]
# Number required for one honest is ceil(($FM_FED_SIZE-1)/3+1)
ONE_HONEST=2
ONE_HONEST_URLS=$(cat $FM_CFG_DIR/client.json | jq --argjson one_honest $ONE_HONEST -e -r '.nodes[:$one_honest] | map(.url) | join(",")')
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
  sleep $POLL_INTERVAL
done
mine_blocks 10
RECEIVED=$($FM_BTC_CLIENT getreceivedbyaddress $PEG_OUT_ADDR)
[[ "$RECEIVED" = "0.00000500" ]]

# LND Gateway Tests
switch_to_lnd_gateway

# OUTGOING: fedimint-cli pays CLN via LND gateaway
INVOICE="$($FM_CLN invoice 100000 lnd-gw-to-cln test 1m | jq -e -r '.bolt11')"
await_cln_block_processing
$FM_MINT_CLIENT ln-pay $INVOICE
# Check that ln-gateway has received the ecash notes from the user payment
# 100,000 sats + 100 sats without processing fee
# FIXME ^^ comment isn't right
FED_ID="$(get_federation_id)"
LN_GATEWAY_BALANCE="$($FM_GWCLI_LND balance $FED_ID | jq -e -r '.balance_msat')"
[[ "$LN_GATEWAY_BALANCE" = "100100000" ]]
INVOICE_RESULT="$($FM_CLN waitinvoice lnd-gw-to-cln)"
INVOICE_STATUS="$(echo $INVOICE_RESULT | jq -e -r '.status')"
[[ "$INVOICE_STATUS" = "paid" ]]

# # INCOMING: User can receive payments via LND gateway
# INVOICE="$($FM_MINT_CLIENT ln-invoice '100000msat' 'integration test' | jq -e -r '.invoice')"
# INVOICE_RESULT=$($FM_CLN pay $INVOICE)
# INVOICE_STATUS="$(echo $INVOICE_RESULT | jq -e -r '.status')"
# [[ "$INVOICE_STATUS" = "complete" ]]

# CLN Gateway Tests
switch_to_cln_gateway

# OUTGOING: fedimint-cli pays LND via CLN gateaway
ADD_INVOICE="$($FM_LND addinvoice --amt_msat 100000)"
INVOICE="$(echo $ADD_INVOICE| jq -e -r '.payment_request')"
PAYMENT_HASH="$(echo $ADD_INVOICE| jq -e -r '.r_hash')"
await_cln_block_processing
$FM_MINT_CLIENT ln-pay $INVOICE
# Check that gateway has received the ecash notes from the user payment
# 100,000 sats + 100 sats without processing fee
# FIXME ^^ comment isnt' right
FED_ID="$(get_federation_id)"
LN_GATEWAY_BALANCE="$($FM_GWCLI_CLN balance $FED_ID | jq -e -r '.balance_msat')"
[[ "$LN_GATEWAY_BALANCE" = "100100000" ]]
INVOICE_STATUS="$($FM_LND lookupinvoice $PAYMENT_HASH | jq -e -r '.state')"
[[ "$INVOICE_STATUS" = "SETTLED" ]]

# INCOMING: User can receive payments via CLN gateway
INVOICE="$($FM_MINT_CLIENT ln-invoice '100000msat' 'incoming-over-lnd-gw' | jq -e -r '.invoice')"
PAYMENT="$($FM_LND payinvoice --force $INVOICE)"
PAYMENT_HASH="$(echo $PAYMENT | awk '{ print $30 }')"
LND_PAYMENTS="$($FM_LND listpayments --include_incomplete)"
PAYMENT_STATUS="$(echo $LND_PAYMENTS | jq -e -r '.payments[] | select(.payment_hash == "'$PAYMENT_HASH'") | .status')"
[[ "$PAYMENT_STATUS" = "SUCCEEDED" ]]

# Lightning Node tests

# LN DIRECT: LND pays CLN directly
INVOICE="$($FM_CLN invoice 42000 lnd-to-cln test 1m | jq -e -r '.bolt11')"
$FM_LND payinvoice --force "$INVOICE"
INVOICE_STATUS="$($FM_CLN waitinvoice lnd-to-cln | jq -e -r '.status')"
[[ "$INVOICE_STATUS" = "paid" ]]

# LN DIRECT: CLN pays LND directly
ADD_INVOICE="$($FM_LND addinvoice --amt_msat 42000)"
INVOICE="$(echo $ADD_INVOICE| jq -e -r '.payment_request')"
PAYMENT_HASH="$(echo $ADD_INVOICE| jq -e -r '.r_hash')"
$FM_CLN pay "$INVOICE"
INVOICE_STATUS="$($FM_LND lookupinvoice $PAYMENT_HASH | jq -e -r '.state')"
[[ "$INVOICE_STATUS" = "SETTLED" ]]
