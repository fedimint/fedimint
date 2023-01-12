# shellcheck shell=bash

export LEGACY_HARDCODED_INSTANCE_ID_WALLET="2"

function mine_blocks() {
    PEG_IN_ADDR="$($FM_BTC_CLIENT getnewaddress)"
    $FM_BTC_CLIENT generatetoaddress $1 $PEG_IN_ADDR
}

function open_channel() {
    LN_ADDR="$($FM_LN1 newaddr | jq -e -r '.bech32')"
    $FM_BTC_CLIENT sendtoaddress $LN_ADDR 1
    mine_blocks 10
    FM_LN2_PUB_KEY="$($FM_LN2 getinfo | jq -e -r '.id')"
    export FM_LN2_PUB_KEY
    FM_LN1_PUB_KEY="$($FM_LN1 getinfo | jq -e -r '.id')"
    export FM_LN1_PUB_KEY
    $FM_LN1 connect $FM_LN2_PUB_KEY@127.0.0.1:9001
    until $FM_LN1 -k fundchannel id=$FM_LN2_PUB_KEY amount=0.1btc push_msat=5000000000; do sleep $POLL_INTERVAL; done
    mine_blocks 10
    until [[ $($FM_LN1 listpeers | jq -e -r ".peers[] | select(.id == \"$FM_LN2_PUB_KEY\") | .channels[0].state") = "CHANNELD_NORMAL" ]]; do sleep $POLL_INTERVAL; done
}

function await_bitcoin_rpc() {
    until $FM_BTC_CLIENT getblockchaininfo; do
        sleep $POLL_INTERVAL
    done
}

function await_cln_rpc() {
    until [ -e $FM_LN1_DIR/regtest/lightning-rpc ]; do
        sleep $POLL_INTERVAL
    done
    until [ -e $FM_LN2_DIR/regtest/lightning-rpc ]; do
        sleep $POLL_INTERVAL
    done
}

function await_fedimint_block_sync() {
  FINALITY_DELAY=$(get_finality_delay)
  EXPECTED_BLOCK_HEIGHT="$(( $($FM_BTC_CLIENT getblockchaininfo | jq -e -r '.blocks') - $FINALITY_DELAY ))"
  echo "Node at ${EXPECTED_BLOCK_HEIGHT}H"
  $FM_MINT_CLIENT wait-block-height $EXPECTED_BLOCK_HEIGHT
  echo "Mint at ${EXPECTED_BLOCK_HEIGHT}H"
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

  # ln1
  until [ $EXPECTED_BLOCK_HEIGHT == "$($FM_LN1 getinfo | jq -e -r '.blockheight')" ]
  do
      sleep $POLL_INTERVAL
  done

  # ln2
  until [ $EXPECTED_BLOCK_HEIGHT == "$($FM_LN2 getinfo | jq -e -r '.blockheight')" ]
  do
      sleep $POLL_INTERVAL
  done
}

# Function for killing processes stored in FM_PID_FILE
function kill_fedimint_processes {
  # shellcheck disable=SC2046
  kill $(cat $FM_PID_FILE | sed '1!G;h;$!d') #sed reverses the order here
  pkill "ln_gateway" || true;
  rm $FM_PID_FILE
}

function start_gateway() {
  $FM_GATEWAY_CLI generate-config '127.0.0.1:8175' 'http://127.0.0.1:8175' $FM_CFG_DIR # generate gateway config
  $FM_LN1 -k plugin subcommand=start plugin=$FM_BIN_DIR/ln_gateway fedimint-cfg=$FM_CFG_DIR &
  sleep 5 # wait for plugin to start
  gw_connect_fed
}

function gw_connect_fed() {
  # connect federation with the gateway
  FM_CONNECT_STR="$($FM_MINT_CLIENT connect-info | jq -e -r '.connect_info')"
  $FM_GATEWAY_CLI connect-fed "$FM_CONNECT_STR"
}

function get_finality_delay() {
    cat $FM_CFG_DIR/client.json | jq -r ".modules.\"${LEGACY_HARDCODED_INSTANCE_ID_WALLET}\".finality_delay"
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
