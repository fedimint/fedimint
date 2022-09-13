#!/usr/bin/env bash

source ./scripts/lib.sh

# First wait 1s for the federation (started itself with a 1s delay after bitcoind)
sleep 2

POLL_INTERVAL=0.5
export POLL_INTERVAL

echo Setting up bitcoind ...
btc_client createwallet default > /dev/null 2>&1
mine_blocks 101 > /dev/null 2>&1

echo Setting up lightning channel ...
open_channel > /dev/null 2>&1

echo Funding user e-cash wallet ...
scripts/pegin.sh 10000.0 > /dev/null 2>&1

echo Funding gateway e-cash wallet ...
scripts/pegin.sh 20000.0 1 > /dev/null 2>&1

echo Done!
echo
echo "This shell provides the following commands:"
echo "  mint-client-cli:  cli client to interact with the federation"
echo "  ln1, ln2:     cli clients for the two lightning nodes (1 is gateway)"
echo "  btc_client:   cli client for bitcoind"
echo
echo Use mint-client-cli as follows:
mint-client-cli --help
