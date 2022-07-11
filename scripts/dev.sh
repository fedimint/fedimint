#!/usr/bin/env bash
# Setup full dev environment

source ./scripts/build.sh
source ./scripts/setup-tests.sh
./scripts/start-fed.sh
./scripts/pegin.sh 0.0001