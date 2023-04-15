#!/usr/bin/env bash
# Runs a test to see what happens if we upgrade consensus

set -euxo pipefail
export RUST_LOG="${RUST_LOG:-info,timing=trace}"

source ./scripts/setup-tests.sh

server4=$(tail -4 $FM_PID_FILE | head -1)
server3=$(tail -3 $FM_PID_FILE | head -1)
server2=$(tail -2 $FM_PID_FILE | head -1)
server1=$(tail -1 $FM_PID_FILE | head -1)


function wait_server_shutdown() {
  >&2 echo "Waiting for $1 to shutdown..."
  tail --pid=$1 -f /dev/null
  echo "Server $1 has shutdown."
}

await_fedimint_block_sync

>&2 echo "### Signal upgrade peer0"
# test a consensus upgrade
FM_PASSWORD="pass0" $FM_MINT_CLIENT signal-upgrade --salt-path $FM_DATA_DIR/server-0/private.salt --our-id 0
>&2 echo "### Signal upgrade peer1"
FM_PASSWORD="pass1" $FM_MINT_CLIENT signal-upgrade --salt-path $FM_DATA_DIR/server-1/private.salt --our-id 1

mine_blocks 1
await_fedimint_block_sync

EPOCH=$($FM_MINT_CLIENT epoch-count | jq -e -r '.count')
FM_UPGRADE_EPOCH=$(echo "$EPOCH + 1" | bc -l)
export FM_UPGRADE_EPOCH
>&2 echo "### Signal upgrade peer2"
FM_PASSWORD="pass2" $FM_MINT_CLIENT signal-upgrade --salt-path $FM_DATA_DIR/server-2/private.salt --our-id 2

>&2 echo "### Wait for server shutdowns"
wait_server_shutdown "$server1"
wait_server_shutdown "$server2"
wait_server_shutdown "$server3"
wait_server_shutdown "$server4"

>&2 echo "### Restart federation"
start_federation

mine_blocks 1
await_fedimint_block_sync
await_all_peers
