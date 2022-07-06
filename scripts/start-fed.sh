#!/usr/bin/env bash
# Generates the configs and starts the federation nodes

set -e
TMP_DIR=${MINIMINT_TEST_DIR:-$1}
FED_SIZE=${FED_SIZE:-4}
SKIPPED_SERVERS=${SKIPPED_SERVERS:-0}

if [ -z $TMP_DIR ]; then echo "TMP_DIR must be set to where the config files will be stored" && exit 1; fi
if [ -z $BIN_DIR ]; then echo "BIN_DIR must be set with the location of the release" && exit 1; fi

echo "Running in $TMP_DIR"
CFG_DIR="$TMP_DIR/cfg"
mkdir -p $CFG_DIR

# Generate federation client config
$BIN_DIR/configgen -- $CFG_DIR $FED_SIZE 4000 5000 1000 10000 100000 1000000 10000000

# FIXME: make db path configurable to avoid cd-ing here
# Start the federation members inside the temporary directory
cd $TMP_DIR
for ((ID=SKIPPED_SERVERS; ID<FED_SIZE; ID++)); do
  echo "starting mint $ID"
  ($BIN_DIR/server $CFG_DIR/server-$ID.json 2>&1 | sed -e "s/^/mint $ID: /" ) &
  echo $! >> $PID_FILE
done

export MINT_CLIENT="$BIN_DIR/mint-client-cli $CFG_DIR"
cd $SRC_DIR

alias mint_client="\$MINT_CLIENT"