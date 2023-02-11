#!/usr/bin/env bash

tmux send-keys -t fedimint-dev:1.5 "pkill -9 fedimintd" C-m
tmux send-keys -t fedimint-dev:1.5 "cargo build --bin fedimintd" C-m
tmux send-keys -t fedimint-dev:1.5 "./scripts/start-fed.sh" C-m

./scripts/gw-reload.sh
