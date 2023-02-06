#!/bin/bash
 
tmux send-keys -t fedimint-dev:1.4 "pkill -9 fedimintd" C-m
tmux send-keys -t fedimint-dev:1.4 "cargo build --bin fedimintd" C-m
tmux send-keys -t fedimint-dev:1.4 "./scripts/start-fed.sh" C-m

./scripts/gw-reload.sh
