#!/bin/bash
# Reload core-lightning gateway plugin

set -euo pipefail

cargo build --bin ln-gateway

$FM_LN1 plugin stop ln-gateway &> /dev/null || true
$FM_LN1 -k plugin subcommand=start plugin=$FM_BIN_DIR/ln-gateway fedimint-cfg=$FM_CFG_DIR &> /dev/null

echo "Gateway plugin reloaded"
