#!/usr/bin/env bash
# Runs a test to determine if upgrading binaries succeeds

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path

old_gatewayd_path=$(nix_build_binary_for_version 'gatewayd' "v0.4.0")
new_gatewayd_path="gatewayd"
old_gateway_cli_path=$(nix_build_binary_for_version 'gateway-cli' "v0.4.0")
new_gateway_cli_path="gateway-cli"
old_gateway_cln_extension_path=$(nix_build_binary_for_version 'gateway-cln-extension' "v0.4.0")
new_gateway_cln_extension_path="gateway-cln-extension"

gateway-tests gatewayd-mnemonic --old-gatewayd-path $old_gatewayd_path --new-gatewayd-path $new_gatewayd_path \
--gw-type lnd \
--old-gateway-cli-path $old_gateway_cli_path --new-gateway-cli-path $new_gateway_cli_path \
--old-gateway-cln-extension-path $old_gateway_cln_extension_path --new-gateway-cln-extension-path $new_gateway_cln_extension_path