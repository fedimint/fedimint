#!/usr/bin/env bash

set -e

# Let's define some shortcuts for bitcoind and the mint client
BTC_CLI="bitcoin-cli -regtest -rpcconnect=127.0.0.1 -rpcuser=bitcoin -rpcpassword=bitcoin"
CLIENT="cargo run --release --bin mint-client cfg"

# Get a peg-in address, which is derived from the federation's descriptor in which every key was tweaked with the same
# random value only known to our client.
ADDR="$($CLIENT peg-in-address)"

# We send the amount we want to peg-in to this address
TX_ID="$($BTC_CLI sendtoaddress $ADDR $1)"

# Now we "wait" for confirmations
$BTC_CLI generatetoaddress 11 "$($BTC_CLI getnewaddress)"
echo waiting 10 seconds for the mints to process the blocks
sleep 10

# We then get a proof from our bitcoind that we sent coins to the peg-in address. This proof can be evaluated by just
# looking at block headers. The federation uses this so that it only needs to be aware of valid block hashes and not
# entire blocks.
TXOUT_PROOF="$($BTC_CLI gettxoutproof "[\"$TX_ID\"]")"
TRANSACTION="$($BTC_CLI getrawtransaction $TX_ID)"

# With these proofs we can instruct the client to start the peg-in process. Our client will add the tweak used to derive
# the peg-in address to the request so that the federation can claim the funds later.
$CLIENT peg-in "$TXOUT_PROOF" "$TRANSACTION"

# Since the process is asynchronous have to come back to fetch the result later. We choose to do this right away and
# just block till we get our tokens.
$CLIENT fetch
