#!/usr/bin/env bash
# Runs a CLI-based integration test

set -euxo pipefail
export RUST_LOG=info

source ./scripts/setup-tests.sh
./scripts/start-fed.sh

FINALITY_DELAY=$(cat $FM_CFG_DIR/server-0.json | jq -r '.wallet.finality_delay')
EXPECTED_BLOCK_HEIGHT="$(( $($FM_BTC_CLIENT getblockchaininfo | jq -r '.blocks') - $FINALITY_DELAY ))"

#start clientd
$FM_CLIENTD $FM_CFG_DIR &
echo $! >> $FM_PID_FILE
await_server_on_port 8081

#### BEGIN TESTS ####
[[ $($FM_CLIENTD_CLI info | jq -r 'has("success")') = true ]]
[[ $($FM_CLIENTD_CLI pending | jq -r 'has("success")') = true ]]
[[ $($FM_CLIENTD_CLI new-peg-in-address | jq -r 'has("success")') = true ]]
ADDR=$($FM_CLIENTD_CLI new-peg-in-address | jq -r '.success.peg_in_address');

#for peg-in we need the TxOutProof and a Transaction
TX_ID="$($FM_BTC_CLIENT sendtoaddress $ADDR 0.001)"
$FM_BTC_CLIENT generatetoaddress 11 "$($FM_BTC_CLIENT getnewaddress)"

#wait until valid (also test the wait-block-height endpoint)
[[ $($FM_CLIENTD_CLI wait-block-height  $EXPECTED_BLOCK_HEIGHT | jq -r 'has("success")') = true ]]

TXOUT_PROOF="$($FM_BTC_CLIENT gettxoutproof "[\"$TX_ID\"]")"
TRANSACTION="$($FM_BTC_CLIENT getrawtransaction $TX_ID)"

#perform peg-in
[[ $($FM_CLIENTD_CLI peg-in $TXOUT_PROOF $TRANSACTION| jq -r 'has("success")') = true ]]