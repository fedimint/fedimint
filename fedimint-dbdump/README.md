# DBDUMP

Fedimint DBDUMP is a tool to dump the contents of the rocksdb in either the client or the server. The path to the database is a required parameter and the range and prefix to dump are optional parameters. Adding a range or a prefix will filter the output of the database by the range within the database and/or the prefix within the range. The prefix is defined by the enum DbKeyPrefix is the respective modules.

For more information on the ranges and prefixes available, see https://github.com/fedimint/fedimint/blob/master/docs/database.md. Table headers are ranges and the Name column are prefixes.

```shell
Usage:
    fedimint-dbdump <path> [--range=<range>] [--prefix=<prefix>]
    
Options:
    --range=<range>    A CSV list of the ranges of the database to dump [default: All].
    --prefix=<prefix>  A CSV list of he prefixes within the range of the database to dump [default: All].

    RANGES=consensus,mint,wallet,lightning,mintclient,lightningclient,walletclient,client
```

Examples:
First, start a tmux so that there is a running federation
```shell
./scripts/tmuxinator.sh
```

Dump the entire database of server-0
```shell
fedimint-dbdump $FM_CFG_DIR/server-0/database
```

Dump the consensus range of server-0
```shell
fedimint-dbdump $FM_CFG_DIR/server-0/database --range=consensus
```

Dump the blocks from within the wallet range of server-1
```shell
fedimint-dbdump $FM_CFG_DIR/server-1/database --range=wallet --prefix=blockhash
```

Dump the used coins from the mint range and the accepted transactions from the consensus range
```shell
fedimint-dbdump $FM_CFG_DIR/server-1/database --range=mint,consensus --prefix=coinnonce,acceptedtransaction
```

Dump the entire client database
```shell
fedimint-dbdump $FM_CFG_DIR/client.db --range=mintclient,lightningclient,walletclient,client
```
