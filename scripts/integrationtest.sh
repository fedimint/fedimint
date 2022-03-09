#!/usr/bin/env bash

set -euxo pipefail

curl https://bitcoincore.org/bin/bitcoin-core-22.0/bitcoin-22.0-x86_64-linux-gnu.tar.gz | sudo tar -xz -C /usr --strip-components=1
curl -L https://github.com/ElementsProject/lightning/releases/download/v0.10.2/clightning-v0.10.2-Ubuntu-20.04.tar.xz | sudo tar -xJv -C /usr --strip-components=2

mkdir -p cfg
cargo build --release
cargo run --release --bin configgen -- cfg 4 4000 5000 1000 10000 100000 1000000 10000000
cargo run --release --bin gw_configgen -- cfg "/tmp/ln1/regtest/lightning-rpc"

# FIXME: deduplicate startfed.sh
bitcoind -regtest -fallbackfee=0.0004 -txindex -server -rpcuser=bitcoin -rpcpassword=bitcoin &
sleep 3

lightningd --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=/tmp/ln1 --addr=127.0.0.1:9000 &
lightningd --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=/tmp/ln2 --addr=127.0.0.1:9001 &

LN1="lightning-cli --network regtest --lightning-dir=/tmp/ln1"
LN2="lightning-cli --network regtest --lightning-dir=/tmp/ln2"

for ((ID=0; ID<4; ID++)); do
  echo "starting mint $ID"
  (RUST_LOG=info,minimint_wallet=trace target/release/server cfg/server-$ID.json 2>&1 | sed -e "s/^/mint $ID: /" ) &
done

sleep 10

RUST_LOG=debug cargo run --release --bin ln_gateway cfg &

# peg in
BTC_CLIENT="bitcoin-cli -regtest -rpcconnect=127.0.0.1 -rpcuser=bitcoin -rpcpassword=bitcoin"
$BTC_CLIENT createwallet main
ADDR="$($BTC_CLIENT getnewaddress)"
$BTC_CLIENT generatetoaddress 120 $ADDR

LN_ADDR="$($LN1 newaddr | jq -r '.bech32')"
$BTC_CLIENT sendtoaddress $LN_ADDR 1

bash ./scripts/pegin.sh 0.00099999

LN2_PUB_KEY="$($LN2 getinfo | jq -r '.id')"
$LN1 connect $LN2_PUB_KEY@127.0.0.1:9001
sleep 5
$LN1 fundchannel $LN2_PUB_KEY 0.1btc

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

INVOICE="$($LN2 invoice 100000 test test 1m | jq -r '.bolt11')"
$MINT_CLIENT ln-pay $INVOICE

INVOICE_STATUS="$($LN2 waitinvoice test | jq -r '.status')"
[[ "$INVOICE_STATUS" = "paid" ]]