#!/usr/bin/env bash
# Runs a test to see what happens if a server dies and rejoins

set -euxo pipefail
export RUST_LOG=info

source ./scripts/setup-tests.sh
./scripts/start-fed.sh

server2=$(tail -2 $FM_PID_FILE | head -1)
server1=$(tail -1 $FM_PID_FILE | head -1)

mine_blocks 110
await_block_sync

kill $server1

mine_blocks 100
await_block_sync

mine_blocks 100
await_block_sync

./scripts/start-fed.sh
# FIXME should await a response from all 4 peers instead of this hack
sleep 5
kill $server2
await_block_sync
