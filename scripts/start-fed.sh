#!/usr/bin/env bash
# Generates the configs and starts the federation nodes

echo "Staring Federation..."
set -euxo pipefail
START_SERVER=${1:-0}
END_SERVER=${2:-$FM_FED_SIZE}

# Start the federation members inside the temporary directory
for ((ID=START_SERVER; ID<END_SERVER; ID++)); do
  echo "starting mint $ID"
  ( ($FM_BIN_DIR/fedimintd $FM_CFG_DIR/server-$ID "pass$ID" 2>&1 & echo $! >&3 ) 3>>$FM_PID_FILE | sed -e "s/^/mint $ID: /" ) &
done

