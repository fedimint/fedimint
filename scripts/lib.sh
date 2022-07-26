function mine_blocks() {
    PEG_IN_ADDR="$($FM_BTC_CLIENT getnewaddress)"
    $FM_BTC_CLIENT generatetoaddress $1 $PEG_IN_ADDR
}

function open_channel() {
    LN_ADDR="$($FM_LN1 newaddr | jq -r '.bech32')"
    $FM_BTC_CLIENT sendtoaddress $LN_ADDR 1
    mine_blocks 10
    export FM_LN2_PUB_KEY="$($FM_LN2 getinfo | jq -r '.id')"
    export FM_LN1_PUB_KEY="$($FM_LN1 getinfo | jq -r '.id')"
    $FM_LN1 connect $FM_LN2_PUB_KEY@127.0.0.1:9001
    until $FM_LN1 -k fundchannel id=$FM_LN2_PUB_KEY amount=0.1btc push_msat=5000000000; do sleep $POLL_INTERVAL; done
    mine_blocks 10
    until [[ $($FM_LN1 listpeers | jq -r ".peers[] | select(.id == \"$FM_LN2_PUB_KEY\") | .channels[0].state") = "CHANNELD_NORMAL" ]]; do sleep $POLL_INTERVAL; done
}

function await_block_sync() {
  FINALTY_DELAY=$(cat $FM_CFG_DIR/server-0.json | jq -r '.wallet.finalty_delay')
  EXPECTED_BLOCK_HEIGHT="$(( $($FM_BTC_CLIENT getblockchaininfo | jq -r '.blocks') - $FINALTY_DELAY ))"
  for ((ID=0; ID<FM_FED_SIZE; ID++)); do
    PORT=$(echo "5000 + $ID" | bc)
    MINT_API_URL="ws://127.0.0.1:$PORT"
    until [ "$($FM_MINT_RPC_CLIENT $MINT_API_URL '/wallet/block_height')" == "$EXPECTED_BLOCK_HEIGHT" ]; do
      sleep $POLL_INTERVAL
    done
  done
}