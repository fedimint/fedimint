#!/usr/bin/env bash

source ./scripts/lib.sh
echo "Run with 'source ./scripts/build.sh [fed_size] [dir]"

# allow for overriding arguments
export FM_FED_SIZE=${1:-4}
BASE_PORT=$((8173 + 10000))

# If $TMP contains '/nix-shell.' it is already unique to the
# nix shell instance, and appending more characters to it is
# pointless. It only gets us closer to the 108 character limit
# for named unix sockets (https://stackoverflow.com/a/34833072),
# so let's not do it.

if [[ "${TMP:-}" == *"/nix-shell."* ]]; then
  FM_TMP_DIR="${2-$TMP}/fm-$(LC_ALL=C tr -dc A-Za-z0-9 </dev/urandom | head -c 4 || true)"
else
  FM_TMP_DIR="${2-"$(mktemp -d)"}"
fi
export FM_TMP_DIR
export FM_TEST_FAST_WEAK_CRYPTO="1"

echo "Setting up env variables in $FM_TMP_DIR"

# Builds the rust executables and sets environment variables
SRC_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
cd $SRC_DIR || exit 1
# Note: Respect 'CARGO_PROFILE' that crane uses
cargo build ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}}

# Define temporary directories to not overwrite manually created config if run locally
export FM_TEST_DIR=$FM_TMP_DIR
export FM_BIN_DIR="$SRC_DIR/target/debug"
export FM_PID_FILE="$FM_TMP_DIR/.pid"
export FM_CLN_DIR="$FM_TEST_DIR/cln"
export FM_LND_DIR="$FM_TEST_DIR/lnd"
export FM_BTC_DIR="$FM_TEST_DIR/bitcoin"
export FM_CFG_DIR="$FM_TEST_DIR/cfg"
export FM_ELECTRS_DIR="$FM_TEST_DIR/electrs"
mkdir -p $FM_CLN_DIR
mkdir -p $FM_LND_DIR
mkdir -p $FM_BTC_DIR
mkdir -p $FM_CFG_DIR

# Copy bitcoind and lnd configs to directories
cp misc/bitcoin.conf $FM_BTC_DIR
cp misc/lnd.conf $FM_LND_DIR

# Generate federation configs
CERTS=""
for ((ID=0; ID<FM_FED_SIZE; ID++));
do
  mkdir $FM_CFG_DIR/server-$ID
  fed_port=$(echo "$BASE_PORT + $ID * 10" | bc -l)
  api_port=$(echo "$BASE_PORT + $ID * 10 + 1" | bc -l)
  export FM_PASSWORD="pass$ID"
  $FM_BIN_DIR/distributedgen create-cert --p2p-url ws://127.0.0.1:$fed_port --api-url ws://127.0.0.1:$api_port --out-dir $FM_CFG_DIR/server-$ID --name "Server-$ID"
  CERTS="$CERTS,$(cat $FM_CFG_DIR/server-$ID/tls-cert)"
done
CERTS=${CERTS:1}
echo "Running DKG with certs: $CERTS"

for ((ID=0; ID<FM_FED_SIZE; ID++));
do
  export FM_PASSWORD="pass$ID"
  fed_port=$(echo "$BASE_PORT + $ID * 10" | bc -l)
  api_port=$(echo "$BASE_PORT + $ID * 10 + 1" | bc -l)
  $FM_BIN_DIR/distributedgen run  --bind-p2p 127.0.0.1:$fed_port --bind-api 127.0.0.1:$api_port --out-dir $FM_CFG_DIR/server-$ID --certs $CERTS &
done
wait

# Move the client config to root dir
mv $FM_CFG_DIR/server-0/client* $FM_CFG_DIR/

# Generate gateway config
export FM_GATEWAY_DATA_DIR=$FM_CFG_DIR/gateway
export FM_GATEWAY_LISTEN_ADDR="127.0.0.1:8175"
export FM_GATEWAY_API_ADDR="http://127.0.0.1:8175"
export FM_GATEWAY_PASSWORD="theresnosecondbest"

export FM_CLN_EXTENSION_LISTEN_ADDRESS="0.0.0.0:8177"
export FM_GATEWAY_LIGHTNING_ADDR="http://localhost:8177"

mkdir -p $FM_GATEWAY_DATA_DIR

# Define clients
export FM_CLN="lightning-cli --network regtest --lightning-dir=$FM_CLN_DIR"
export FM_LND="lncli -n regtest --lnddir=$FM_LND_DIR --rpcserver=localhost:11009"
export FM_BTC_CLIENT="bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin"
export FM_MINT_CLIENT="$FM_BIN_DIR/fedimint-cli --workdir $FM_CFG_DIR"
export FM_MINT_RPC_CLIENT="$FM_BIN_DIR/mint-rpc-client"
export FM_GWCLI_CLN="$FM_BIN_DIR/gateway-cli --rpcpassword=theresnosecondbest"
export FM_GWCLI_LND="$FM_BIN_DIR/gateway-cli --rpcpassword=theresnosecondbest -a http://127.0.0.1:18175/"
export FM_DB_TOOL="$FM_BIN_DIR/dbtool"
export FM_DISTRIBUTEDGEN="$FM_BIN_DIR/distributedgen"

# Gatewayd parameters

# Alias clients
alias lightning-cli="\$FM_CLN"
alias lncli="\$FM_LND"
alias bitcoin-cli="\$FM_BTC_CLIENT"
alias mint_client="\$FM_MINT_CLIENT"
alias mint_rpc_client="\$FM_MINT_RPC_CLIENT"
alias gateway-cln="\$FM_GWCLI_CLN"
alias gateway-lnd="\$FM_GWCLI_LND"
alias dbtool="\$FM_DB_TOOL"
alias distributedgen="\$FM_DISTRIBUTEDGEN"

trap kill_fedimint_processes EXIT
