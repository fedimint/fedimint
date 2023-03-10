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

# Required by tests to manipulate bitcoind
export FM_TEST_BITCOIND_RPC="http://bitcoin:bitcoin@127.0.0.1:18443"
export FM_BITCOIND_RPC="http://bitcoin:bitcoin@127.0.0.1:18443"

until [ "$($FM_BTC_CLIENT getblockchaininfo | jq -e -r '.chain')" == "regtest" ]; do
  sleep $POLL_INTERVAL
done
$FM_BTC_CLIENT createwallet ""

# Start electrs
ELECTRS_CFG="$FM_TEST_DIR/electrs.toml"
echo 'auth = "bitcoin:bitcoin"' > $ELECTRS_CFG
echo 'daemon_rpc_addr = "127.0.0.1:18443"' >> $ELECTRS_CFG
echo 'daemon_p2p_addr = "127.0.0.1:18444"' >> $ELECTRS_CFG
echo 'electrum_rpc_addr = "127.0.0.1:50001"' >> $ELECTRS_CFG
electrs --network "regtest" --conf "$ELECTRS_CFG" --db-dir "$FM_TEST_DIR/electrs" --daemon-dir "$FM_BTC_DIR" &
echo $! >> $FM_PID_FILE

# Start esplora
esplora --cookie "bitcoin:bitcoin" --network "regtest" --daemon-dir "$FM_BTC_DIR" --http-addr "127.0.0.1:50002" --daemon-rpc-addr "127.0.0.1:18443" --monitoring-addr "127.0.0.1:50003" --db-dir "$FM_TEST_DIR/esplora" &
echo $! >> $FM_PID_FILE

if [[ "$(lightningd --bitcoin-cli "$(which false)" --dev-no-plugin-checksum 2>&1 )" =~ .*"--dev-no-plugin-checksum: unrecognized option".* ]]; then
  LIGHTNING_FLAGS=""
else
  LIGHTNING_FLAGS="--dev-fast-gossip --dev-bitcoind-poll=1"
fi

# Start lightning nodes
lightningd $LIGHTNING_FLAGS --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=$FM_LN1_DIR --addr=127.0.0.1:9000 --plugin=$FM_BIN_DIR/gateway-cln-extension &
echo $! >> $FM_PID_FILE
lightningd $LIGHTNING_FLAGS --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=$FM_LN2_DIR --addr=127.0.0.1:9001 &
echo $! >> $FM_PID_FILE
await_cln_rpc

# Initialize wallet and get ourselves some money
mine_blocks 101

# Open channel
open_channel
