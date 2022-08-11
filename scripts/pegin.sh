#!/usr/bin/env bash
# Calls the CLI to peg user client into the federation
echo "Run with 'source ./scripts/pegin.sh [amount] [use_gateway]"

set -euxo pipefail
source ./scripts/lib.sh

# Let's define some shortcuts for bitcoind and the mint client
POLL_INTERVAL=1
export POLL_INTERVAL
# Bitcoin amount in satoshi

PEG_IN_AMOUNT=${PEG_IN_AMOUNT:-$1}
USE_GATEWAY=${2:-0}

FINALITY_DELAY=$(get_finality_delay)
echo "Pegging in $PEG_IN_AMOUNT with confirmation in $FINALITY_DELAY blocks"

# get a peg-in address from either the gateway or the client
if [ "$USE_GATEWAY" == 1 ]; then ADDR="$($FM_LN1 -H gw-address)"; else ADDR="$($FM_MINT_CLIENT peg-in-address)"; fi
# send bitcoin to that address and save the txid
TX_ID=$(send_bitcoin $ADDR $PEG_IN_AMOUNT)
# wait for confirmation and wait for the fed to sync
mine_blocks 11
await_block_sync
#get the txoutproof and the raw transaction from the txid
TXOUT_PROOF=$(get_txout_proof $TX_ID)
TRANSACTION=$(get_raw_transaction $TX_ID)

# With these proofs we can instruct the client to start the peg-in process. Our client will add the tweak used to derive
# the peg-in address to the request so that the federation can claim the funds later.
if [ "$USE_GATEWAY" == 1 ]; then $FM_LN1 gw-deposit "$TXOUT_PROOF" "$TRANSACTION"; else $FM_MINT_CLIENT peg-in "$TXOUT_PROOF" "$TRANSACTION"; fi

# Since the process is asynchronous have to come back to fetch the result later. We choose to do this right away and
# just block till we get our tokens.
$FM_MINT_CLIENT fetch