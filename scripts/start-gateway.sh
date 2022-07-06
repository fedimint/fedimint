#!/usr/bin/env bash
# Generates the configs and starts the LN gateway server

set -e
TMP_DIR=${MINIMINT_TEST_DIR:-$1}
CFG_DIR="$TMP_DIR/cfg"
mkdir -p $CFG_DIR

if [ -z $TMP_DIR ]; then echo "TMP_DIR must be set to where the config files will be stored" && exit 1; fi
if [ -z $BIN_DIR ]; then echo "BIN_DIR must be set with the location of the release" && exit 1; fi
if [ -z $LN1_DIR ]; then echo "LN1_DIR must be set" && exit 1; fi
if [ -z $LN1_PUB_KEY ]; then echo "LN1_PUB_KEY must be set" && exit 1; fi

$BIN_DIR/gw_configgen -- $CFG_DIR "$LN1_DIR/regtest/lightning-rpc" $LN1_PUB_KEY

# Start LN gateway
$BIN_DIR/ln_gateway $CFG_DIR &
echo $! >> $PID_FILE