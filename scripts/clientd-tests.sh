#!/usr/bin/env bash
# Runs a CLI-based integration test

set -euxo pipefail
export RUST_LOG=info

source ./scripts/setup-tests.sh
./scripts/start-fed.sh

#start clientd
$FM_CLIENTD $FM_CFG_DIR &
echo $! >> $FM_PID_FILE
await_server_on_port 8081

#### BEGIN TESTS ####
[[ $($FM_CLIENTD_CLI info | jq -r 'has("success")') = true ]]
[[ $($FM_CLIENTD_CLI pending | jq -r 'has("success")') = true ]]
[[ $($FM_CLIENTD_CLI new-peg-in-address | jq -r 'has("success")') = true ]]