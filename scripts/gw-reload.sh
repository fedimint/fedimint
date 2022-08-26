#!/bin/bash
# Reload core-lightning gateway plugin

set -euo pipefail

cargo build --release --bin ln_gateway
$LN1 plugin stop ln_gateway &> /dev/null
$LN1 -k plugin subcommand=start plugin=$BIN_DIR/ln_gateway fedimint-cfg=$CFG_DIR &> /dev/null

echo "Gateway plugin reloaded"
