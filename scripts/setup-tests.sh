#!/usr/bin/env bash

set -u

echo "Setting up tests..."

FM_FED_SIZE=${1:-4}

source ./scripts/build.sh $FM_FED_SIZE

# Starts Bitcoin and 2 LN nodes, opening a channel between the LN nodes
POLL_INTERVAL=1

# Start bitcoind and wait for it to become ready
bitcoind -datadir=$FM_BTC_DIR &
echo $! >> $FM_PID_FILE

until [ "$($FM_BTC_CLIENT getblockchaininfo | jq -e -r '.chain')" == "regtest" ]; do
  sleep $POLL_INTERVAL
done
$FM_BTC_CLIENT createwallet ""

# Start electrs
electrs --conf-dir "$FM_ELECTRS_DIR" --db-dir "$FM_ELECTRS_DIR" --daemon-dir "$FM_BTC_DIR" &
echo $! >> $FM_PID_FILE

# Start esplora
esplora --cookie "bitcoin:bitcoin" --network "regtest" --daemon-dir "$FM_BTC_DIR" --http-addr "127.0.0.1:50002" --daemon-rpc-addr "127.0.0.1:18443" --monitoring-addr "127.0.0.1:50003" --db-dir "$FM_TEST_DIR/esplora" &
echo $! >> $FM_PID_FILE

if [[ "$(lightningd --bitcoin-cli "$(which false)" --dev-no-plugin-checksum 2>&1 )" =~ .*"--dev-no-plugin-checksum: unrecognized option".* ]]; then
  LIGHTNING_FLAGS=""
else
  LIGHTNING_FLAGS="--dev-fast-gossip --dev-bitcoind-poll=1"
fi

# Start Core Lightning
lightningd $LIGHTNING_FLAGS --lightning-dir=$FM_CLN_DIR --plugin=$FM_BIN_DIR/gateway-cln-extension &
echo $! >> $FM_PID_FILE

# Start LND
lnd --lnddir=$FM_LND_DIR &
echo $! >> $FM_PID_FILE

# Initialize wallet and get ourselves some money
mine_blocks 101

# Open channel
open_channel
