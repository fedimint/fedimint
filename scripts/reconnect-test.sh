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

function kill_server() {
  echo "Killing server $1..."
  kill $1
  tail --pid=$1 -f /dev/null
  echo "Killed server $1..."
}

function generate_epochs() {
  for ((I=0; I<$1; I++)); do
    mine_blocks 10
    await_block_sync
  done
}

mine_blocks 110
await_block_sync
await_all_peers

# test a peer missing out on epochs and needing to rejoin
kill_server $server1
# FIXME increase this number once we can avoid processing epoch messages too far in the future
generate_epochs 1

./scripts/start-fed.sh
# FIXME increase this number once we can avoid processing epoch messages too far in the future
generate_epochs 1
await_all_peers
echo "Server 1 successfully rejoined!"

## now test what happens if consensus needs to be restarted
kill_server $server2
mine_blocks 100
await_block_sync
kill_server $server3
kill_server $server4

./scripts/start-fed.sh
await_all_peers
echo "Successfully restarted consensus!"
