#!/usr/bin/env bash
#
# Start a devimint-env with an extra WebSocket API on peer 0,
# fronted by a Tor onion service. Prints the onion address so
# you can test connecting through Tor.
#
# Usage:
#   ./scripts/dev/devimint-env-tor-test.sh
#
# Requires `tor` to be in $PATH.

set -euo pipefail

LOCAL_WS_PORT=1234
ONION_PORT=80 # virtual port clients connect to
TOR_SOCKS_PORT=auto # let Tor pick an available port

if ! command -v tor &>/dev/null; then
  echo >&2 "Error: 'tor' not found in PATH"
  exit 1
fi

TOR_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fedimint-tor-test.XXXXXX")

cleanup() {
  if [ -n "${TOR_PID:-}" ]; then
    kill "$TOR_PID" 2>/dev/null || true
    wait "$TOR_PID" 2>/dev/null || true
  fi
  rm -rf "$TOR_DIR"
}
trap cleanup EXIT

cat > "$TOR_DIR/torrc" <<EOF
SocksPort $TOR_SOCKS_PORT
DataDirectory $TOR_DIR/data
HiddenServiceDir $TOR_DIR/hidden_service
HiddenServicePort $ONION_PORT 127.0.0.1:$LOCAL_WS_PORT
EOF

mkdir -m 700 "$TOR_DIR/hidden_service"

TOR_LOG="$TOR_DIR/tor.log"
echo >&2 "Starting Tor (state in $TOR_DIR)..."
tor -f "$TOR_DIR/torrc" > "$TOR_LOG" 2>&1 &
TOR_PID=$!

# Wait for Tor to generate the onion address
while [ ! -f "$TOR_DIR/hidden_service/hostname" ]; do
  if ! kill -0 "$TOR_PID" 2>/dev/null; then
    echo >&2 "Error: Tor exited unexpectedly. Log:"
    cat >&2 "$TOR_LOG"
    exit 1
  fi
  sleep 0.5
done

ONION_ADDR=$(cat "$TOR_DIR/hidden_service/hostname")

echo >&2 "========================================"
echo >&2 "Tor onion address: $ONION_ADDR"
echo >&2 "Forwarding: $ONION_ADDR:$ONION_PORT -> 127.0.0.1:$LOCAL_WS_PORT"
echo >&2 "Connect:    ws://$ONION_ADDR"
echo >&2 "========================================"

export FM_DEVIMINT_FEDIMINTD_0_BIND_EXTRA_WEBSOCKET_API="127.0.0.1:$LOCAL_WS_PORT"
exec just devimint-env
