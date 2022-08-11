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

# Get a peg-in address, which is derived from the federation's descriptor in which every key was tweaked with the same
# random value only known to our client.
if [ "$USE_GATEWAY" == 1 ]; then ADDR="$($FM_LN1 -H gw-address)"; else ADDR="$($FM_MINT_CLIENT peg-in-address)"; fi

# We send the amount we want to peg-in to this address
TX_ID="$($FM_BTC_CLIENT sendtoaddress $ADDR "$(sat_to_btc $PEG_IN_AMOUNT)")"

# Now we "wait" for confirmations
$FM_BTC_CLIENT generatetoaddress 11 "$($FM_BTC_CLIENT getnewaddress)"
await_block_sync

# We then get a proof from our bitcoind that we sent coins to the peg-in address. This proof can be evaluated by just
# looking at block headers. The federation uses this so that it only needs to be aware of valid block hashes and not
# entire blocks.
TXOUT_PROOF="$($FM_BTC_CLIENT gettxoutproof "[\"$TX_ID\"]")"
TRANSACTION="$($FM_BTC_CLIENT getrawtransaction $TX_ID)"

# With these proofs we can instruct the client to start the peg-in process. Our client will add the tweak used to derive
# the peg-in address to the request so that the federation can claim the funds later.
if [ "$USE_GATEWAY" == 1 ]; then $FM_LN1 gw-deposit "$TXOUT_PROOF" "$TRANSACTION"; else $FM_MINT_CLIENT peg-in "$TXOUT_PROOF" "$TRANSACTION"; fi

# Since the process is asynchronous have to come back to fetch the result later. We choose to do this right away and
# just block till we get our tokens.
$FM_MINT_CLIENT fetch