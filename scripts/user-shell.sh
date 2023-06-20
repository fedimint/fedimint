# shellcheck shell=bash

eval "$(devimint env)"
source ./scripts/completion.sh
source ./scripts/aliases.sh

function show_verbose_output()
{
    if [[ $FM_VERBOSE_OUTPUT -ne 1 ]]
    then
        cat > /dev/null 2>&1
    else
        cat
    fi
}

function use_cln_gw() {
    PUBKEY=$($FM_LIGHTNING_CLI getinfo | jq -e -r '.id')
    $FM_MINT_CLIENT switch-gateway $PUBKEY
    echo "Using CLN gateway"
}

function use_lnd_gw() {
    PUBKEY=$($FM_LNCLI getinfo | jq -e -r '.identity_pubkey')
    $FM_MINT_CLIENT switch-gateway $PUBKEY
    echo "Using LND gateway"
}

echo Waiting for fedimint start

STATUS="$(devimint wait)"
if [ "$STATUS" = "ERROR" ]
then
    echo "fedimint didn't start correctly"
    echo "See other panes for errors"
    exit 1
fi

scripts/pegin.sh 10000.0 | show_verbose_output

use_cln_gw

echo Funding CLN gateway e-cash wallet ...
scripts/pegin.sh 20000.0 1 | show_verbose_output
echo Funding LND gateway e-cash wallet ...
scripts/pegin.sh 20000.0 1 "LND" | show_verbose_output

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
