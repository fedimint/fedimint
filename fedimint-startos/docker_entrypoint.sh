#!/bin/bash

set -e

# Find the entrypoint script dynamically
ENTRYPOINT_SCRIPT=$(find /nix/store -type f -name '*-fedimintd-container-entrypoint.sh' | head -n 1)

if [[ -z "$ENTRYPOINT_SCRIPT" ]]; then
    echo "Error: fedimintd-container-entrypoint.sh not found in /nix/store" >&2
    exit 1
fi

echo "Waiting for Start9 config..."
while [ ! -f /start-os/start9/config.yaml ]; do
    sleep 1
done

echo "Config file found at /start-os/start9/config.yaml"

export FM_DATA_DIR=/fedimintd
export FM_BITCOIN_NETWORK=bitcoin
export FM_BIND_UI=0.0.0.0:8175
export FM_ENABLE_IROH=true

# Read and set RUST_LOG from config
RUST_LOG_LEVEL=$(yq '.rust-log-level' /start-os/start9/config.yaml)
export RUST_LOG="${RUST_LOG_LEVEL}"
echo "Setting RUST_LOG=${RUST_LOG}"

# Config file structure:
# fedimintd-bitcoin-backend:
#   backend-type: <bitcoind|esplora>
#   user: <username>           # only for bitcoind
#   password: <password>       # only for bitcoind
#   url: 'https://...'         # only for esplora

# Parse configuration using yq
BACKEND_TYPE=$(yq '.fedimintd-bitcoin-backend.backend-type' /start-os/start9/config.yaml)

if [ "$BACKEND_TYPE" = "bitcoind" ]; then
    echo "Using Bitcoin Core backend"
    BITCOIN_USER=$(yq '.fedimintd-bitcoin-backend.user' /start-os/start9/config.yaml)
    BITCOIN_PASS=$(yq '.fedimintd-bitcoin-backend.password' /start-os/start9/config.yaml)

    if [ -z "$BITCOIN_USER" ] || [ -z "$BITCOIN_PASS" ]; then
        echo "ERROR: Could not parse Bitcoin RPC credentials from config"
        exit 1
    fi

    export FM_BITCOIND_URL="http://bitcoind.embassy:8332"
    export FM_BITCOIND_USERNAME="${BITCOIN_USER}"
    export FM_BITCOIND_PASSWORD="${BITCOIN_PASS}"

    echo "Starting Fedimint with Bitcoin Core at $FM_BITCOIND_URL"
elif [ "$BACKEND_TYPE" = "esplora" ]; then
    echo "Using Esplora backend"
    ESPLORA_URL=$(yq '.fedimintd-bitcoin-backend.url' /start-os/start9/config.yaml)

    if [ -z "$ESPLORA_URL" ]; then
        echo "ERROR: Could not parse Esplora URL from config"
        exit 1
    fi

    export FM_ESPLORA_URL="$ESPLORA_URL"
    echo "Starting Fedimint with Esplora at $ESPLORA_URL"
else
    echo "ERROR: Unknown backend type: $BACKEND_TYPE"
    exit 1
fi

# Create .backupignore to exclude files that shouldn't be backed up:
#
# We exclude the active database because:
# - `database/` is the live RocksDB instance that may be in an inconsistent state during backup
# - Backing up active databases can lead to corruption
#
# Instead, we rely on `db_checkpoints/` which contains:
# - Periodic consistent snapshots of the federation state
# - Safe restore points that allow rejoining the federation
# - Much faster sync than starting from genesis (session 0)
if [ ! -f /fedimintd/.backupignore ]; then
    echo "Creating .backupignore file..."
    cat > /fedimintd/.backupignore <<EOF
database
database.db.lock
EOF
fi

# Check if we need to restore from checkpoint (after a backup restore)
if [ ! -d "/fedimintd/database" ] && [ -d "/fedimintd/db_checkpoints" ]; then
    echo "Database directory not found, checking for restore from checkpoint..."

    # Find the single checkpoint directory (there should only be one)
    CHECKPOINT=$(ls -1 /fedimintd/db_checkpoints)

    if [ -n "$CHECKPOINT" ]; then
        echo "Found checkpoint: $CHECKPOINT"
        echo "Restoring database from checkpoint..."

        # Create the database directory and copy checkpoint files
        mkdir -p /fedimintd/database
        cp -r /fedimintd/db_checkpoints/"$CHECKPOINT"/* /fedimintd/database/

        echo "Database restored from checkpoint $CHECKPOINT"
    else
        echo "No checkpoint found to restore from"
    fi
else
    echo "Database directory exists, proceeding with normal startup"
fi

exec bash "$ENTRYPOINT_SCRIPT" "$@"
