#!/usr/bin/env bash

set -euo pipefail

REQUIRED_BINS=(jq fedimint-cli)
for REQUIRED_BIN in "${REQUIRED_BINS[@]}"; do
    if ! which "$REQUIRED_BIN" &> /dev/null; then
        echo "$REQUIRED_BIN is not installed."
        exit 1
    fi
done

if [ -z "${1:-}" ]; then
    echo "Error: No directory specified."
    echo "Usage: $0 <data_directory>"
    exit 1
fi
DATA_DIR=$1

echo "This script will add the meta module to federation config, which is technically"
echo "a consensus-breaking change. Make sure that:"
echo "  * All fedimintd instances are shut down"
echo "  * You run this script on all of them"
echo "  * Only restart once all are patched"
echo "  * Let them run for a bit after restarting before voting on meta module"
echo "    consensus proposals"
echo ""
echo -e "\e[1mIt's like open heart surgery on a federation, please only continue if you know\e[0m"
echo -e "\e[1mwhat you are doing and can debug Fedimint problems yourself.\e[0m"
echo ""
echo -n "Do you wish to continue? (yes/no): "
read response

if [[ "$response" != "yes" ]]; then
    echo "Operation aborted by the user."
    exit 1
fi

exists=$(jq '.modules | to_entries | any(.value.kind == "meta")' "$DATA_DIR/consensus.json")
if [ "$exists" == "true" ]; then
    echo "A module of kind 'meta' already exists."
    exit 1
fi

NEXT_MOD_ID="$(jq '[.modules | keys[] | tonumber] | max + 1' "$DATA_DIR/consensus.json")"

mv "$DATA_DIR/consensus.json" "$DATA_DIR/consensus.json.bak"
mv "$DATA_DIR/local.json" "$DATA_DIR/local.json.bak"
mv "$DATA_DIR/private.encrypt" "$DATA_DIR/private.encrypt.bak"

PASSWORD="$(cat "$DATA_DIR/password.private")"
fedimint-cli dev config-decrypt --in-file "$DATA_DIR/private.encrypt.bak" --out-file "$DATA_DIR/private.json.old" "$PASSWORD" > /dev/null

jq --arg next_mod_id "$NEXT_MOD_ID" '.modules_json += {($next_mod_id): {"kind": "meta"}} | .modules += {($next_mod_id): {"kind": "meta", "version": {"major": 0, "minor": 0}, "config": ""}}' "$DATA_DIR/consensus.json.bak" > "$DATA_DIR/consensus.json"
jq --arg next_mod_id "$NEXT_MOD_ID" '.modules += {($next_mod_id): {"kind": "meta"}}' "$DATA_DIR/local.json.bak" > "$DATA_DIR/local.json"
jq --arg next_mod_id "$NEXT_MOD_ID" '.modules += {($next_mod_id): {"kind": "meta"}}' "$DATA_DIR/private.json.old" > "$DATA_DIR/private.json.new"

fedimint-cli dev config-encrypt --in-file "$DATA_DIR/private.json.new" --out-file "$DATA_DIR/private.encrypt" "$PASSWORD" > /dev/null

rm "$DATA_DIR/private.json.old" "$DATA_DIR/private.json.new"

echo "Config files in $DATA_DIR have been patched, you can start fedimintd again."
echo -e "\e[1mONLY VOTE ON META VALUES ONCE ALL GUARDIANS ARE UPGRADED\e[0m"