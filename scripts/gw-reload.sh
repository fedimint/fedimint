#!/usr/bin/env bash
# Reload core-lightning gateway plugin

set -euo pipefail

cargo build ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} --bin gateway-cln-extension

$FM_LIGHTNING_CLI plugin stop ln_gateway &> /dev/null || true
$FM_LIGHTNING_CLI -k plugin subcommand=start plugin=$FM_BIN_DIR/gateway-cln-extension &> /dev/null

echo "Gateway plugin reloaded"
