#!/usr/bin/env bash

set -u

echo "Setting up tests..."

FM_FED_SIZE=${1:-4}

source ./scripts/build.sh $FM_FED_SIZE

# start daemons
start_fixtures
start_electrs
start_esplora

# Run DKG and start federation
run_dkg
start_federation

# Open channel
open_channel
