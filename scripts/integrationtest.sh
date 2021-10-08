#!/usr/bin/env bash

set -euxo pipefail

curl https://bitcoincore.org/bin/bitcoin-core-22.0/bitcoin-22.0-x86_64-linux-gnu.tar.gz | sudo tar -xz -C /usr --strip-components=1
mkdir -p cfg
cargo build --release --all-targets
cargo run --release --bin configgen -- cfg 4 4000 5000 1000 10000 100000 1000000 10000000

# FIXME: deduplicate startfed.sh
cargo build --release --all-targets

bitcoind -regtest -fallbackfee=0.0004 -txindex -server -rpcuser=bitcoin -rpcpassword=bitcoin &
sleep 3

for ((ID=0; ID<4; ID++)); do
  echo "starting mint $ID"
  (RUST_LOG=info,minimint_wallet=trace target/release/server cfg/server-$ID.json 2>&1 | sed -e "s/^/mint $ID: /" ) &
done

sleep 10

# peg in
BTC_CLIENT="bitcoin-cli -regtest -rpcconnect=127.0.0.1 -rpcuser=bitcoin -rpcpassword=bitcoin"
$BTC_CLIENT createwallet main
ADDR="$($BTC_CLIENT getnewaddress)"
$BTC_CLIENT generatetoaddress 120 $ADDR
bash ./scripts/pegin.sh 0.00099999

# reissue
MINT_CLIENT="cargo run --release --bin mint-client cfg"
TOKENS=$($MINT_CLIENT spend 42000)
$MINT_CLIENT reissue $TOKENS
$MINT_CLIENT fetch

# peg out
PEG_OUT_ADDR="$($BTC_CLIENT getnewaddress)"
$MINT_CLIENT peg-out $PEG_OUT_ADDR "500 sat"
sleep 5
$BTC_CLIENT generatetoaddress 120 $ADDR
sleep 20
$BTC_CLIENT generatetoaddress 10 $ADDR
sleep 5
RECEIVED=$($BTC_CLIENT getreceivedbyaddress $PEG_OUT_ADDR)
[[ "$RECEIVED" = "0.00000500" ]]