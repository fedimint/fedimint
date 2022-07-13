#!/usr/bin/env bash
# Calls the CLI to peg into the federation

set -euxo pipefail

# Let's define some shortcuts for bitcoind and the mint client
POLL_INTERVAL=1
PEG_IN_AMOUNT=${PEG_IN_AMOUNT:-$1}

CONFIRMATION_TIME=$(cat $FM_CFG_DIR/server-0.json | jq -r '.wallet.finalty_delay')
echo "Pegging in $PEG_IN_AMOUNT with confirmation time $CONFIRMATION_TIME"

# Get a peg-in address, which is derived from the federation's descriptor in which every key was tweaked with the same
# random value only known to our client.
ADDR="$($FM_MINT_CLIENT peg-in-address)"

# We send the amount we want to peg-in to this address
TX_ID="$($FM_BTC_CLIENT sendtoaddress $ADDR $PEG_IN_AMOUNT)"

# Now we "wait" for confirmations
$FM_BTC_CLIENT generatetoaddress 11 "$($FM_BTC_CLIENT getnewaddress)"

function await_block_sync() {
  EXPECTED_BLOCK_HEIGHT="$(( $($FM_BTC_CLIENT getblockchaininfo | jq -r '.blocks') - $CONFIRMATION_TIME ))"
  for ((ID=0; ID<FM_FED_SIZE; ID++)); do
    PORT=$(echo "5000 + $ID" | bc)
    MINT_API_URL="ws://127.0.0.1:$PORT"
    until [ "$($FM_MINT_RPC_CLIENT $MINT_API_URL '/wallet/block_height')" == "$EXPECTED_BLOCK_HEIGHT" ]; do
      sleep $POLL_INTERVAL
    done
  done
}
await_block_sync

# We then get a proof from our bitcoind that we sent coins to the peg-in address. This proof can be evaluated by just
# looking at block headers. The federation uses this so that it only needs to be aware of valid block hashes and not
# entire blocks.
TXOUT_PROOF="$($FM_BTC_CLIENT gettxoutproof "[\"$TX_ID\"]")"
TRANSACTION="$($FM_BTC_CLIENT getrawtransaction $TX_ID)"

# With these proofs we can instruct the client to start the peg-in process. Our client will add the tweak used to derive
# the peg-in address to the request so that the federation can claim the funds later.
$FM_MINT_CLIENT peg-in "$TXOUT_PROOF" "$TRANSACTION"

# Since the process is asynchronous have to come back to fetch the result later. We choose to do this right away and
# just block till we get our tokens.
$FM_MINT_CLIENT fetch
