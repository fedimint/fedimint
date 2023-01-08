#!/usr/bin/env bash

source ./scripts/lib.sh

POLL_INTERVAL=0.5
export POLL_INTERVAL

# wait for cln, bitcoind and fedimint servers to start up
await_bitcoin_rpc
await_cln_rpc
await_fedimint_block_sync

echo Setting up bitcoind ...
btc_client createwallet default | show_verbose_output
mine_blocks 101 | show_verbose_output

echo Setting up lightning channel ...
open_channel | show_verbose_output

echo Funding user e-cash wallet ...
scripts/pegin.sh 10000.0 | show_verbose_output

echo Connecting federation to gateway
gw_connect_fed

echo Funding gateway e-cash wallet ...
scripts/pegin.sh 20000.0 1 | show_verbose_output

echo Done!
echo
echo "This shell provides the following commands:"
echo "  fedimint-cli:  cli client to interact with the federation"
echo "  ln1, ln2:     cli clients for the two lightning nodes (1 is gateway)"
echo "  btc_client:   cli client for bitcoind"
echo "  gateway-cli:  cli client for the gateway"
echo
echo Use fedimint-cli as follows:
fedimint-cli --help
