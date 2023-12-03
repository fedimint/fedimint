# `dbtool`

**CAUTION: `dbtool` is a potentially destructive expert-tool, handle with care and if in doubt make a copy of your
database.**

For database layout see [`database.md`](../docs/database.md), but verify the information in the code before taking
potentially destructive action.

If your federation is running, a database lock should cause a panic when running these commands so be sure to stop
the federation first.

## Usage
```
$ fedimint-dbtool --help
Tool to inspect and manipulate rocksdb databases. All binary arguments (keys, values) have to be hex encoded

Usage: fedimint-dbtool <DATABASE> <COMMAND>

Commands:
  list    List all key-value pairs where the key begins with `prefix`
  write   Write a key-value pair to the database, overwriting the previous value if present
  delete  Delete a single entry from the database identified by `key`
  dump    Dump the database (or a subset) to the console as a json serialized string
  help    Print this message or the help of the given subcommand(s)

Arguments:
  <DATABASE>  - file path of the database

Options:
  -h, --help  Print help
```

## Deleting multiple elements

Other than the `list` command, the `delete` command only works on single keys. To delete entire key prefixes you can use
standard unix tools to build that functionality:

```bash
fedimint-dbtool <DATABASE> list <PREFIX> | cut -d ' ' -f 1 | xargs -n 1 -- fedimint-dbtool <DATABASE> delete
```

* `cut` selects a column from the space-separated output of `fedimint-dbtool`
  * `-d ' '` sets its delimiter to space
  * `-f 1` selects the first column
* `xargs` calls `fedimint-dbtool delete <key>` for each line of input
  * `-n 1` specifies that only one element will be passed to the specified command at a time

## Hex encoding

To en-/decode hex you can use `xxd`, although the raw binary data will not be of use that often.

```
$ echo -n "my binary data ..." | xxd -ps -c 0
6d792062696e6172792064617461202e2e2e

$ echo "6d792062696e6172792064617461202e2e2e" | xxd -r -p
my binary data ...

## Dump

The dump command can be used to dump a json-serialized portion of the database. Dump takes two required parameters <CFG_DIR> and <PASSWORD>. Password is used to decrypt the configuration file so the dbtool understand the type of module.
The dump command also takes optional parameters <MODULE> and <PREFIX> to dump only a subset of the database.

For more information on the modules and prefixes available to dump, see https://github.com/fedimint/fedimint/blob/master/docs/database.md. Table headers are modules and the Name column are prefixes.

Examples:
First, run a local federation in mprocs:
```shell
just mprocs
```

Dump the entire database of fedimintd-0
```shell
fedimint-dbtool $FM_DATA_DIR/fedimintd-0/database dump -- $FM_DATA_DIR/fedimintd-0 pass
```

Dump the consensus db entries of fedimintd-0
```shell
fedimint-dbtool $FM_DATA_DIR/fedimintd-0/database dump -- $FM_DATA_DIR/fedimintd-0 pass consensus
```

Dump the blocks from the wallet module of fedimintd-1
```shell
fedimint-dbtool $FM_DATA_DIR/fedimintd-1/database dump -- $FM_DATA_DIR/fedimintd-1 pass consensus blockhash
```

Dump the used notes from the mint module and the accepted transactions from consensus
```shell
fedimint-dbtool $FM_DATA_DIR/fedimintd-1/database dump -- $FM_DATA_DIR/fedimintd-1 pass consensus,mint notenonce,acceptedtransaction
```

Dump the entire client database (client password can be anything since it doesn't require decryption)
```shell
fedimint-dbtool $FM_CLIENT_DIR/client.db dump $FM_CLIENT_DIR clientpass client
```
