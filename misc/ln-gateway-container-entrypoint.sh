#!/usr/bin/env bash

if [ "$1" == "gateway-cli" ]; then
 exec "$@"
fi

exec ln_gateway "$@"
