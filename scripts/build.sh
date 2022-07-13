#!/usr/bin/env bash
echo "Run with 'source ./scripts/build.sh [fed_size] [dir]"

# allow for overriding arguments
export FED_SIZE=${1:-4}
export TMP_DIR=${2-"$(mktemp -d)"}
echo "Setting up env variables in $TMP_DIR"

# Builds the rust executables and sets environment variables
SRC_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
cd $SRC_DIR
cargo build --release

# Define temporary directories to not overwrite manually created config if run locally
export MINIMINT_TEST_DIR=$TMP_DIR
export BIN_DIR="$SRC_DIR/target/release"
export PID_FILE="$TMP_DIR/.pid"
export LN1_DIR="$MINIMINT_TEST_DIR/ln1"
export LN2_DIR="$MINIMINT_TEST_DIR/ln2"
export BTC_DIR="$MINIMINT_TEST_DIR/bitcoin"
export CFG_DIR="$MINIMINT_TEST_DIR/cfg"
mkdir -p $LN1_DIR
mkdir -p $LN2_DIR
mkdir -p $BTC_DIR
mkdir -p $CFG_DIR

# Generate federation client config
$BIN_DIR/configgen -- $CFG_DIR $FED_SIZE 4000 5000 1000 10000 100000 1000000 10000000

# Define clients
export LN1="lightning-cli --network regtest --lightning-dir=$LN1_DIR"
export LN2="lightning-cli --network regtest --lightning-dir=$LN2_DIR"
export BTC_CLIENT="bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin"
export MINT_CLIENT="$BIN_DIR/mint-client-cli $CFG_DIR"
export MINT_RPC_CLIENT="$BIN_DIR/mint-rpc-client"

# Alias clients
alias ln1="\$LN1"
alias ln2="\$LN2"
alias btc_client="\$BTC_CLIENT"
alias mint_client="\$MINT_CLIENT"
alias mint_rpc_client="\$MINT_RPC_CLIENT"

# Function for killing processes stored in PID_FILE
function kill_minimint_processes {
  kill $(cat $PID_FILE | sed '1!G;h;$!d') #sed reverses the order here
  pkill "ln_gateway";
  rm $PID_FILE
}
trap kill_minimint_processes EXIT