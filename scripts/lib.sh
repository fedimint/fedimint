# shellcheck shell=bash

export LEGACY_HARDCODED_INSTANCE_ID_WALLET="2"

function mine_blocks() {
    PEG_IN_ADDR="$($FM_BTC_CLIENT getnewaddress)"
    $FM_BTC_CLIENT generatetoaddress $1 $PEG_IN_ADDR
}

function open_channel() {
    LN_ADDR="$($FM_CLN newaddr | jq -e -r '.bech32')"
    $FM_BTC_CLIENT sendtoaddress $LN_ADDR 1
    mine_blocks 10
    FM_LND_PUB_KEY=$($FM_LND getinfo | jq -r ".identity_pubkey")
    $FM_CLN connect $FM_LND_PUB_KEY@127.0.0.1:9734
    until $FM_CLN -k fundchannel id=$FM_LND_PUB_KEY amount=0.1btc push_msat=5000000000; do sleep $POLL_INTERVAL; done
    mine_blocks 10
    until [[ $($FM_CLN listpeers | jq -e -r ".peers[] | select(.id == \"$FM_LND_PUB_KEY\") | .channels[0].state") = "CHANNELD_NORMAL" ]]; do sleep $POLL_INTERVAL; done
}

function await_bitcoin_rpc() {
    until $FM_BTC_CLIENT getblockchaininfo 1>/dev/null 2>/dev/null ; do
        >&2 echo "Bitcoind rpc not ready yet. Waiting ..."
        sleep "$POLL_INTERVAL"
    done
}

function await_cln_start() {
    until [ -e "$FM_CLN_DIR/regtest/lightning-rpc" ]; do
        >&2 echo "CLN gateway not ready yet. Waiting ..."
        sleep "$POLL_INTERVAL"
    done
}

function await_lnd_start() {
    until [ -e "$FM_LND_DIR/data/chain/bitcoin/regtest/admin.macaroon" ]; do
        >&2 echo "LND not ready yet. Waiting ..."
        sleep "$POLL_INTERVAL"
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
      sleep $POLL_INTERVAL
  done
}

# Check that core-lightning block-proccessing is caught up
# CLI integration tests should call this before attempting to pay invoices
function await_cln_block_processing() {
  EXPECTED_BLOCK_HEIGHT="$($FM_BTC_CLIENT getblockchaininfo | jq -e -r '.blocks')"

  # cln
  until [ $EXPECTED_BLOCK_HEIGHT == "$($FM_CLN getinfo | jq -e -r '.blockheight')" ]
  do
      sleep $POLL_INTERVAL
  done

  # lnd
  until [ "true" == "$($FM_LND getinfo | jq -r '.synced_to_chain')" ]
  do
    sleep $POLL_INTERVAL
  done
}

# Function for killing processes stored in FM_PID_FILE
function kill_fedimint_processes {
  # shellcheck disable=SC2046
  kill $(cat $FM_PID_FILE | sed '1!G;h;$!d') 2>/dev/null #sed reverses the order here
  rm -f $FM_PID_FILE
}

function start_gatewayd() {
  # start cln gw
  export FM_GATEWAY_DATA_DIR=$FM_TEST_DIR/gw1
  export FM_GATEWAY_LISTEN_ADDR="127.0.0.1:8175"
  export FM_GATEWAY_API_ADDR="http://127.0.0.1:8175"
  $FM_BIN_DIR/gatewayd &
  echo $! >> $FM_PID_FILE

  # start lnd gw
  unset FM_GATEWAY_LIGHTNING_ADDR
  export FM_GATEWAY_DATA_DIR=$FM_TEST_DIR/gw2
  export FM_GATEWAY_LISTEN_ADDR="127.0.0.1:18175"
  export FM_GATEWAY_API_ADDR="http://127.0.0.1:18175"
  export FM_LND_RPC_ADDR="http://localhost:11009"
  export FM_LND_TLS_CERT=$FM_LND_DIR/tls.cert
  export FM_LND_MACAROON=$FM_LND_DIR/data/chain/bitcoin/regtest/admin.macaroon
  $FM_BIN_DIR/gatewayd &
  echo $! >> $FM_PID_FILE

  echo "started gatewayd"
  connect_gateways
}

function connect_gateways() {
  # connect federation with the gateway
  FM_CONNECT_STR="$($FM_MINT_CLIENT connect-info | jq -e -r '.connect_info')"
  $FM_GWCLI_CLN connect-fed "$FM_CONNECT_STR"
  $FM_GWCLI_LND connect-fed "$FM_CONNECT_STR"
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
    until [ "$($FM_MINT_CLIENT list-gateways | jq -e ".num_gateways")" -gt "0" ]; do
        sleep $POLL_INTERVAL
    done
}

function switch_to_cln_gateway() {
    echo "switching to CLN gateway"
    echo
    # FIXME: we should have a better way to filter than by API url
    local PUBKEY
    PUBKEY=$($FM_MINT_CLIENT list-gateways | jq -e '.gateways[] | select(.api == "http://127.0.0.1:8175/")' | jq -r -e '.node_pub_key')
    $FM_MINT_CLIENT switch-gateway $PUBKEY
    echo "switched to CLN gateway"
    echo
}

function switch_to_lnd_gateway() {
    echo "switching to LND gateway"
    echo
    # FIXME: we should have a better way to filter than by API url
    local PUBKEY
    PUBKEY=$($FM_MINT_CLIENT list-gateways | jq -e '.gateways[] | select(.api == "http://127.0.0.1:18175/")' | jq -r -e '.node_pub_key')
    $FM_MINT_CLIENT switch-gateway $PUBKEY
    echo "switched to LND gateway"
    echo
}
