#!/usr/bin/env bash
# Generates the configs and starts the federation nodes

set -euxo pipefail
SKIPPED_SERVERS=${SKIPPED_SERVERS:-0}

# Start the federation members inside the temporary directory
for ((ID=SKIPPED_SERVERS; ID<FM_FED_SIZE; ID++)); do
  echo "starting mint $ID"
  ( ($FM_BIN_DIR/server $FM_CFG_DIR/server-$ID.json $FM_CFG_DIR/mint-$ID.db 2>&1 & echo $! >&3 ) 3>>$FM_PID_FILE | sed -e "s/^/mint $ID: /" ) &
done
