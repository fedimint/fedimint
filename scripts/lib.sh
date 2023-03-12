# shellcheck shell=bash

export LEGACY_HARDCODED_INSTANCE_ID_WALLET="2"

function mine_blocks() {
    PEG_IN_ADDR="$($FM_BTC_CLIENT getnewaddress)"
    $FM_BTC_CLIENT generatetoaddress $1 $PEG_IN_ADDR
}

function open_channel() {
    # check that both nodes are synced
    await_lightning_node_block_processing

    LN_ADDR="$($FM_LIGHTNING_CLI newaddr | jq -e -r '.bech32')"
    $FM_BTC_CLIENT sendtoaddress $LN_ADDR 1
    mine_blocks 10
    LND_PUBKEY="$($FM_LNCLI getinfo | jq -e -r '.identity_pubkey')"
    $FM_LIGHTNING_CLI connect $LND_PUBKEY@127.0.0.1:9734
    until $FM_LIGHTNING_CLI -k fundchannel id=$LND_PUBKEY amount=0.1btc push_msat=5000000000; do sleep $FM_POLL_INTERVAL; done
    mine_blocks 10
    until [[ $($FM_LIGHTNING_CLI listpeers | jq -e -r ".peers[] | select(.id == \"$LND_PUBKEY\") | .channels[0].state") = "CHANNELD_NORMAL" ]]; do sleep $FM_POLL_INTERVAL; done
}

function await_bitcoin_rpc() {
    until $FM_BTC_CLIENT getblockchaininfo 1>/dev/null 2>/dev/null ; do
        >&2 echo "Bitcoind rpc not ready yet. Waiting ..."
        sleep "$FM_POLL_INTERVAL"
    done
}

function await_fedimint_block_sync() {
  local node_height
  local finality_delay
  local expected_block_height

  node_height="$($FM_BTC_CLIENT getblockchaininfo | jq -e -r '.blocks')"
  finality_delay="$(get_finality_delay)"
  expected_block_height="$((node_height - finality_delay))"

  echo "Node at ${node_height}H"

  if [ 0 -lt $expected_block_height ]; then
      $FM_MINT_CLIENT wait-block-height $expected_block_height
  fi
}

function await_all_peers() {
  $FM_MINT_CLIENT api /module/${LEGACY_HARDCODED_INSTANCE_ID_WALLET}/block_height
}

function await_server_on_port() {
  until nc -z 127.0.0.1 $1
  do
      sleep $FM_POLL_INTERVAL
  done
}

# Check that lightning block-proccessing is caught up
# CLI integration tests should call this before attempting to pay invoices
function await_lightning_node_block_processing() {
  # CLN
  EXPECTED_BLOCK_HEIGHT="$($FM_BTC_CLIENT getblockchaininfo | jq -e -r '.blocks')"
  until [ $EXPECTED_BLOCK_HEIGHT == "$($FM_LIGHTNING_CLI getinfo | jq -e -r '.blockheight')" ]
  do
    sleep $FM_POLL_INTERVAL
  done
  echo "done waiting for cln"

  # LND
  until [ "true" == "$($FM_LNCLI getinfo | jq -r '.synced_to_chain')" ]
  do
    echo "sleeping"
    sleep $FM_POLL_INTERVAL
  done
  echo "done waiting for lnd"
}

# Function for killing processes stored in FM_PID_FILE
function kill_fedimint_processes {
  # shellcheck disable=SC2046
  kill $(cat $FM_PID_FILE | sed '1!G;h;$!d') 2>/dev/null #sed reverses the order here
  rm -f $FM_PID_FILE
}

function await_gateway_cln_extension() {
  while ! echo exit | nc localhost 8177; do sleep $FM_POLL_INTERVAL; done
}

function gw_connect_fed() {
  # connect federation with the gateway
  FM_CONNECT_STR="$($FM_MINT_CLIENT connect-info | jq -e -r '.connect_info')"
  until $FM_GATEWAY_CLI connect-fed "$FM_CONNECT_STR"
  do
    echo "gateway-cli connect-fed failed ... retrying"
    sleep 1
  done
}

function get_finality_delay() {
    cat $FM_CFG_DIR/client.json | jq -e -r ".modules.\"${LEGACY_HARDCODED_INSTANCE_ID_WALLET}\".config.finality_delay"
}

function sat_to_btc() {
    echo "scale=8; $1/100000000" | bc | awk '{printf "%.8f\n", $0}'
}

#caller should call mine_blocks() after this
function send_bitcoin() {
    local RECV_ADDRESS
    RECV_ADDRESS=$1
    local SEND_AMT
    SEND_AMT=$2

    local TX_ID
    TX_ID="$($FM_BTC_CLIENT sendtoaddress $RECV_ADDRESS "$(sat_to_btc $SEND_AMT)")"
    echo $TX_ID
}

function get_txout_proof() {
    local TX_ID
    TX_ID=$1

    local TXOUT_PROOF
    TXOUT_PROOF="$($FM_BTC_CLIENT gettxoutproof "[\"$TX_ID\"]")"
    echo $TXOUT_PROOF
}

function get_raw_transaction() {
    local TX_ID
    TX_ID=$1

    local TRANSACTION
    TRANSACTION="$($FM_BTC_CLIENT getrawtransaction $TX_ID)"
    echo $TRANSACTION
}

function get_federation_id() {
    cat $FM_CFG_DIR/client.json | jq -e -r '.federation_id'
}

function show_verbose_output()
{
    if [[ $FM_VERBOSE_OUTPUT -ne 1 ]] 
    then
        cat > /dev/null 2>&1
    else
        cat
    fi
}

function await_gateway_registered() {
    until [ "$($FM_MINT_CLIENT list-gateways | jq -e ".num_gateways")" = "1" ]; do
        sleep $FM_POLL_INTERVAL
    done
}

function run_dkg() {
  # Generate federation configs
  BASE_PORT=$((8173 + 10000))
  CERTS=""
  for ((ID=0; ID<FM_FED_SIZE; ID++));
  do
    echo "making dir"
    mkdir $FM_CFG_DIR/server-$ID
    FED_PORT=$(echo "$BASE_PORT + $ID * 10" | bc -l)
    API_PORT=$(echo "$BASE_PORT + $ID * 10 + 1" | bc -l)
    export FM_PASSWORD="pass$ID"
    echo "making creating cert for port $FED_PORT $API_PORT"
    RUST_BACKTRACE=1 $FM_BIN_DIR/distributedgen create-cert --p2p-url ws://127.0.0.1:$FED_PORT --api-url ws://127.0.0.1:$API_PORT --out-dir $FM_CFG_DIR/server-$ID --name "Server-$ID"
    CERTS="$CERTS,$(cat $FM_CFG_DIR/server-$ID/tls-cert)"
  done
  CERTS=${CERTS:1}
  echo "Running DKG with certs: $CERTS"

  DKG_PIDS=""
  for ((ID=0; ID<FM_FED_SIZE; ID++));
  do
    export FM_PASSWORD="pass$ID"
    fed_port=$(echo "$BASE_PORT + $ID * 10" | bc -l)
    api_port=$(echo "$BASE_PORT + $ID * 10 + 1" | bc -l)
    $FM_BIN_DIR/distributedgen run  --bind-p2p 127.0.0.1:$fed_port --bind-api 127.0.0.1:$api_port --out-dir $FM_CFG_DIR/server-$ID --certs $CERTS &
    DKG_PIDS="$DKG_PIDS $!"
  done
  wait $DKG_PIDS

  # Move the client config
  mv $FM_CFG_DIR/server-0/client* $FM_CFG_DIR/
}

### Start Daemons ###

function start_bitcoind() {
  echo "starting bitcoind"
  bitcoind -datadir=$FM_BTC_DIR &
  echo $! >> $FM_PID_FILE
  await_bitcoin_rpc
  # create a default RPC wallet
  $FM_BTC_CLIENT createwallet ""
  # mine some blocks
  mine_blocks 101
  echo "started bitcoind"
}

function start_lightningd() {
  echo "starting lightningd"
  await_bitcoin_rpc
  # if we're running developer build, enable some flags to make it lightningd run faster
  if [[ "$(lightningd --bitcoin-cli "$(which false)" --dev-no-plugin-checksum 2>&1 )" =~ .*"--dev-no-plugin-checksum: unrecognized option".* ]]; then
    LIGHTNING_FLAGS=""
  else
    LIGHTNING_FLAGS="--dev-fast-gossip --dev-bitcoind-poll=1"
  fi
  lightningd $LIGHTNING_FLAGS --lightning-dir=$FM_CLN_DIR --plugin=$FM_BIN_DIR/gateway-cln-extension &
  echo $! >> $FM_PID_FILE
  echo "started lightningd"
}

function start_lnd() {
  echo "starting lnd"
  await_bitcoin_rpc
  lnd --lnddir=$FM_LND_DIR &
  echo $! >> $FM_PID_FILE
  echo "started lnd"
}

function start_gatewayd() {
  echo "starting gatewayd"
  await_gateway_cln_extension
  await_fedimint_block_sync
  $FM_BIN_DIR/gatewayd &
  echo $! >> $FM_PID_FILE
  gw_connect_fed
  echo "started gatewayd"
}

function start_electrs() {
  echo "starting electrs"
  await_bitcoin_rpc
  electrs --conf-dir "$FM_ELECTRS_DIR" --db-dir "$FM_ELECTRS_DIR" --daemon-dir "$FM_BTC_DIR" &
  echo $! >> $FM_PID_FILE
  echo "started electrs"
}

function start_esplora() {
  echo "starting esplora"
  await_bitcoin_rpc
  esplora --cookie "bitcoin:bitcoin" --network "regtest" --daemon-dir "$FM_BTC_DIR" --http-addr "127.0.0.1:50002" --daemon-rpc-addr "127.0.0.1:18443" --monitoring-addr "127.0.0.1:50003" --db-dir "$FM_TEST_DIR/esplora" &
  echo $! >> $FM_PID_FILE
  echo "started esplora"
}

function start_federation() {
  echo "starting federation"
  await_bitcoin_rpc

  START_SERVER=${1:-0}
  END_SERVER=${2:-$FM_FED_SIZE}

  # Start the federation members inside the temporary directory
  for ((ID=START_SERVER; ID<END_SERVER; ID++)); do
    echo "starting mint $ID"
    export FM_PASSWORD="pass$ID"
    ( ($FM_BIN_DIR/fedimintd $FM_CFG_DIR/server-$ID 2>&1 & echo $! >&3 ) 3>>$FM_PID_FILE | sed -e "s/^/mint $ID: /" ) &
  done
  echo "started federation"
}
