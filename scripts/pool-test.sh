# shellcheck shell=bash

PEGINADDRESS=$(seeker-cli peg-in-address | jq -r '.address')
# this default amount suggested by copilot, open to changes
PEGINTXID=$(send_bitcoin $PEGINADDRESS 100000000)
mine_blocks 11
TXOUTPROOF=$(get_txout_proof $PEGINTXID)
TRANSACTION=$(get_raw_transaction $PEGINTXID)
seeker-cli peg-in $TXOUTPROOF $TRANSACTION
seeker-cli fetch
seeker-cli info

PEGINADDRESS=$(provider-cli peg-in-address | jq -r '.address')
# this default amount suggested by copilot, open to changes
PEGINTXID=$(send_bitcoin $PEGINADDRESS 100000000)
mine_blocks 11
TXOUTPROOF=$(get_txout_proof $PEGINTXID)
TRANSACTION=$(get_raw_transaction $PEGINTXID)
provider-cli peg-in $TXOUTPROOF $TRANSACTION
provider-cli fetch
provider-cli info

# test these: pool-staged-seeker-action, pool-staged-provider-bid, pool-balance, pool-epoch-outcome, pool-staging-epoch, pool-deposit, pool-withdraw, pool-action

provider-cli pool-deposit 80000000
provider-cli pool-balance
provider-cli pool-withdraw 5000000

seeker-cli pool-deposit 80000000
seeker-cli pool-balance

THIS_EPOCH=$(seeker-cli pool-staging-epoch | jq -r '.epoch_id')
LAST_EPOCH=$(($THIS_EPOCH - 1))
seeker-cli pool-epoch-outcome $LAST_EPOCH
