#!/bin/bash

set -e

# Find the entrypoint script dynamically
ENTRYPOINT_SCRIPT=$(find /nix/store -type f -name '*-fedimintd-container-entrypoint.sh' | head -n 1)

if [[ -z "$ENTRYPOINT_SCRIPT" ]]; then
    echo "Error: fedimintd-container-entrypoint.sh not found in /nix/store" >&2
    exit 1
fi

export FM_FORCE_IROH=1
export FM_BITCOIN_NETWORK=signet
export FM_BITCOIN_RPC_KIND=esplora
export FM_BITCOIN_RPC_URL=https://mutinynet.com/api
export FM_DEFAULT_ESPLORA_API=https://mutinynet.com/api
export FM_BIND_UI=0.0.0.0:8175
export FM_DATA_DIR=/fedimintd

exec bash "$ENTRYPOINT_SCRIPT" "$@"
