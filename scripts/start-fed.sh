#!/usr/bin/env bash
# Generates the configs and starts the federation nodes

set -euxo pipefail
SKIPPED_SERVERS=${SKIPPED_SERVERS:-0}

# FIXME: make db path configurable to avoid cd-ing here
# Start the federation members inside the temporary directory
cd $CFG_DIR
for ((ID=SKIPPED_SERVERS; ID<FED_SIZE; ID++)); do
  echo "starting mint $ID"
  ($BIN_DIR/server $CFG_DIR/server-$ID.json 2>&1 | sed -e "s/^/mint $ID: /" ) &
  echo $! >> $PID_FILE
done