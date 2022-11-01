#!/usr/bin/env bash
# Generates the configs and starts the federation nodes

echo "Staring Federation..."
set -euxo pipefail
SKIPPED_SERVERS=${1:-0}

# Start the federation members inside the temporary directory
for ((ID=SKIPPED_SERVERS; ID<FM_FED_SIZE; ID++)); do
  echo "starting mint $ID"
  ( ($FM_BIN_DIR/fedimintd $FM_CFG_DIR/server-$ID "pass$ID" 2>&1 & echo $! >&3 ) 3>>$FM_PID_FILE | sed -e "s/^/mint $ID: /" ) &
done

