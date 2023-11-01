# shellcheck shell=bash

eval "$(devimint env)"
source ./scripts/dev/completion.sh
source ./scripts/dev/aliases.sh

echo Waiting for fedimint start

STATUS="$(devimint wait)"
if [ "$STATUS" = "ERROR" ]
then
    echo "fedimint didn't start correctly"
    echo "See other panes for errors"
    exit 1
fi

eval "$(devimint env)"

echo Done!
echo
echo "This shell provides the following aliases:"
echo ""
echo "  fedimint-cli   - cli client to interact with the federation"
echo "  lightning-cli  - cli client for Core Lightning"
echo "  lncli          - cli client for LND"
echo "  bitcoin-cli    - cli client for bitcoind"
echo "  gateway-cln    - cli client for the CLN gateway"
echo "  gateway-lnd    - cli client for the LND gateway"
echo
echo "Use '--help' on each command for more information"
