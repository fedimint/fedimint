#!/usr/bin/env bash

source ./scripts/lib.sh

POLL_INTERVAL=0.5
export POLL_INTERVAL

function await_next_epoch() {
    local EPOCH_ID
    EPOCH_ID=$1

    echo "[ Wait for EPOCH_NEXT == ${EPOCH_ID} ]"
    while [[ $EPOCH_ID -gt "$($FM_S_CLIENT pool epoch-next 2> /dev/null | jq '.epoch_next.epoch_id')" ]]; do sleep 1; done
    echo "  * EPOCH_NEXT is now ${EPOCH_ID}"
    echo ""
}

function oracle_set_price() {
    local PRICE
    PRICE=$1

    echo "[ Setting ORACLE_PRICE = ${PRICE} cents/BTC ]"
    echo ${PRICE} > misc/offline_oracle
    echo "  * ORACLE_PRICE is now ${PRICE} cents/BTC"
    echo ""
    sleep 1
}

function seeker() {
    echo "(SEEKER) \$ fedimint-cli $*"
    echo "$($FM_S_CLIENT "$@")"
    echo ""
}

function provider_a() {
    echo "(PROVIDER A) \$ fedimint-cli $*"
    echo "$($FM_A_CLIENT "$@")"
    echo ""
}

function provider_b() {
    echo "(PROVIDER B) \$ fedimint-cli $*"
    echo "$($FM_B_CLIENT "$@")"
    echo ""
}

function all_balances() {
    seeker pool balance
    provider_a pool balance
    provider_b pool balance
}

# wait for cln, bitcoind and fedimint servers to start up
await_bitcoin_rpc | show_verbose_output
await_cln_rpc | show_verbose_output
await_fedimint_block_sync | show_verbose_output

echo Setting up bitcoind ...
bitcoin-cli createwallet default | show_verbose_output
mine_blocks 101 | show_verbose_output

echo Setting up lightning channel ...
open_channel | show_verbose_output

echo Funding user e-cash wallets ...
# scripts/pegin.sh 10000.0 | show_verbose_output
scripts/pegin.sh 10000.0 0 "${FM_S_CLIENT}" | show_verbose_output
scripts/pegin.sh 10000.0 0 "${FM_A_CLIENT}" | show_verbose_output
scripts/pegin.sh 10000.0 0 "${FM_B_CLIENT}" | show_verbose_output

echo Connecting federation to gateway
gw_connect_fed

echo Funding gateway e-cash wallet ...
scripts/pegin.sh 20000.0 1 | show_verbose_output
echo ""
echo "[ STARTING SCRIPT ]"
echo ""
echo ""
echo "# Let's deposit some funds!"
echo ""
provider_a pool deposit 10000000
provider_b pool deposit 10000000
seeker pool deposit 10000000
echo ""

await_next_epoch 3 && oracle_set_price 1000000 && all_balances # $10,000

echo ""
echo "# Epoch 3: Price goes up"
echo ""

provider_a pool action provider-bid 1000 10000000
seeker pool action seeker-lock 5000000

await_next_epoch 4 && oracle_set_price 2000000 && all_balances # $20,000

echo ""
echo "# Epoch 4: Price goes up again"
echo ""

await_next_epoch 5 && oracle_set_price 3000000 && all_balances # $30,000

echo ""
echo "# Epoch 5: Provider B steps in with a better rate, but price drops"
echo ""

provider_b pool action provider-bid 500 10000000

await_next_epoch 6 && oracle_set_price 2100000 && all_balances

echo ""
echo "# Epoch 6: Both providers pull out"
echo ""

provider_a pool action provider-bid 0 0
provider_b pool action provider-bid 0 0

await_next_epoch 7 && oracle_set_price 2000000 && all_balances
