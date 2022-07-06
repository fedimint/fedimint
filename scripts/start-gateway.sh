#!/usr/bin/env bash
# Generates the configs and starts the LN gateway server

set -euxo pipefail

$BIN_DIR/gw_configgen -- $CFG_DIR "$LN1_DIR/regtest/lightning-rpc" $LN1_PUB_KEY

# Start LN gateway
$BIN_DIR/ln_gateway $CFG_DIR &
echo $! >> $PID_FILE