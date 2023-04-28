# shellcheck shell=bash

function mine_blocks() {
    PEG_IN_ADDR="$($FM_BTC_CLIENT getnewaddress)"
    $FM_BTC_CLIENT generatetoaddress $1 $PEG_IN_ADDR
}

function await_fedimint_block_sync() {
  BLOCKS="$($FM_BTC_CLIENT getblockchaininfo | jq -e -r '.blocks')"
  FINALITY_DELAY=10
  AWAIT="$((BLOCKS - FINALITY_DELAY))"
  echo "await_fedimint_block_sync $AWAIT"
  $FM_MINT_CLIENT wait-block-height "$AWAIT"
}

# Function for killing processes stored in FM_PID_FILE in reverse-order they were created in
function kill_fedimint_processes {
  echo "Killing fedimint processes"
  PIDS=$(cat $FM_PID_FILE | sed '1!G;h;$!d') # sed reverses order
  if [ -n "$PIDS" ]
  then
    kill $PIDS 2>/dev/null
  fi
  rm -f $FM_PID_FILE
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
    cat $FM_DATA_DIR/client.json | jq -e -r '.federation_id'
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

function use_cln_gw() {
    PUBKEY=$($FM_LIGHTNING_CLI getinfo | jq -e -r '.id')
    $FM_MINT_CLIENT switch-gateway $PUBKEY
    echo "Using CLN gateway"
}

function use_lnd_gw() {
    PUBKEY=$($FM_LNCLI getinfo | jq -e -r '.identity_pubkey')
    $FM_MINT_CLIENT switch-gateway $PUBKEY
    echo "Using LND gateway"
}
