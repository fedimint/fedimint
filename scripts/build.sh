#!/usr/bin/env bash
# Builds the rust executables

SRC_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
cd $SRC_DIR
cargo build --release
export BIN_DIR="$SRC_DIR/target/release"