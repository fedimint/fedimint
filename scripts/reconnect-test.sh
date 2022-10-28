#!/usr/bin/env bash
# Runs a test to see what happens if a server dies and rejoins

set -euxo pipefail
export RUST_LOG=info

source ./scripts/setup-tests.sh
./scripts/start-fed.sh

server4=$(tail -4 $FM_PID_FILE | head -1)
server3=$(tail -3 $FM_PID_FILE | head -1)
server2=$(tail -2 $FM_PID_FILE | head -1)
server1=$(tail -1 $FM_PID_FILE | head -1)

mine_blocks 110
await_block_sync

# FIXME should await a response from all 4 peers instead of this hack
sleep 15

# test a peer missing out on epochs and needing to rejoin
echo "Kill server1..."
kill $server1
mine_blocks 100
await_block_sync
mine_blocks 100
await_block_sync
./scripts/start-fed.sh

# FIXME should await a response from all 4 peers instead of this hack
sleep 15
echo "Kill server2..."
kill $server2
await_block_sync

# now test what happens if consensus needs to be restarted
sleep 15
echo "Kill server3..."
kill $server3
echo "Kill server4..."
kill $server4
sleep 15
./scripts/start-fed.sh
mine_blocks 100
await_block_sync
