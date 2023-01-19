## Running Fedimint for dev testing

Fedimint consists of three kinds of executables:

* **Federation nodes** - servers who form the mint by running a consensus protocol
* **Lightning gateways** - allows users send and receive over Lightning by bridging between the mint and an LN node
* **User clients** - handles user communication with the mint and the gateway

### Prerequisites

In order to run Fedimint you will need:
- The [Rust toolchain](https://www.rust-lang.org/tools/install) to build and run the executables
- The [Nix package manager](https://nixos.org/download.html) for managing build and test dependencies

Clone and `cd` into the Fedimint repo:

```shell
git clone git@github.com:fedimint/fedimint.git
cd fedimint
```

It's recommended to **start all the commands in "Nix dev shell"**, which can be started with `nix develop` command.

### Setting up the federation

Just run the following script, **make sure not to run it inside a tmux window**:

```shell
./scripts/tmuxinator.sh
```
which will set up a complete federation including a lightning gateway and another lightning node inside tmux. The first run can take some time since a lot of dependencies need to be built.

The first tmux screen is one big shell for you to follow the tutorial in. If you want to see the federation, bitcoind and lightningd running you can navigate to the second screen (shown below) by typing `ctrl+b, n` (next) and `ctrl+b, p` (previous). You can scroll through the terminal buffer by first typing `ctrl+b, PgUp` and then navigating using `PgUp` and `PgDown`. To maximize any of the panes type `ctrl+b, z`. 
To end the whole tmuxinator session and terminate all the services which were started type `ctrl+b, :kill-session` and hit `Enter`.

![screenshot of the federation running in tmux](tmuxinator.png)

### Using the client

Note as you run commands the mint nodes will output logging information which you can adjust by setting the [RUST_LOG](https://docs.rs/env_logger/latest/env_logger/) env variable.

The previous step has already set up an e-cash client with a funded wallet for you. If you are interested in the details take a look at [`scripts/pegin.sh`](../scripts/pegin.sh).

You can view your client's holdings using the `info` command:

```shell
$ fedimint-cli info

{
  "info": {
    "network" : "Regtest",
    "total_amount": 120005000,
    "total_num_notes": 17,
    "details":  {
      "1000": 5,
      "10000000": 12,
    }
  }
}
```

The `spend` subcommand allows sending notes to another client. This will select the smallest possible set of the client's notes that represents a given amount.
The notes are base64 encoded into a token and printed as the `token` field.

```shell
$ fedimint-cli spend 400000

{
  "spend": {
    "token": "AQAAAAAAAACAlpgAAAAAAAEAA..."
  }
}
```

The `validate` subcommand checks the validity of the signatures without claiming the notes. It does not check if the nonce is unspent. Validity will be printed as the `all_valid` boolean.

```shell
$ fedimint-cli validate AQAAAAAAAABAQg8AAA...

{
  "validate": {
    "all_valid": true,
    "details": {}
  }
}
```

A receiving client can now reissue these notes to claim them and avoid double spends:

```shell
$ fedimint-cli reissue AQAAAAAAAABAQg8AAA...
> ...

$ fedimint-cli fetch

{
  "fetch": {
    "issuance": [
      {
        "txid": "46f2948b772ae8b8...",
        "out_idx": 0
      }
    ]
  }
}
```

### Using the Gateway

First let's have the gateway execute a peg-in so it has an ecash token balance. We can use the same `pegin.sh` script as before, but add an extra parameter to tell it to use the gateway:

```shell
$ ./scripts/pegin.sh 10000 1
```

Make a note of the federation id from the previous step, or run `gateway-cli info` and copy the federation id.

Now we can use `gateway-cli` of the node where the gateway plugin is running to get our ecash token balance:

```shell
$ gateway-cli balance <FEDERATION-ID>
{
   "balance_msat": 10000000
}
```

To make an outgoing payment we generate a Lightning invoice from LN2, our non-gateway lightning node:

```shell
$ ln2 invoice 100000 test test 1m

{
   "bolt11": "lnbcrt1u1p3vdl3ds...",
   ...
}
```

Pay the invoice by copying the `bolt11` invoice field:

```shell
$ fedimint-cli ln-pay "lnbcrt1u1p3vdl3ds..."
```

Confirm the invoice was paid

```shell
$ ln2 listinvoices test

{
   "invoices": [
      {
         "label": "test",
         "status": "paid",
         ...
      }
   ]
}
```

Create our own invoice:
```shell
$ fedimint-cli ln-invoice 1000 "description"

{
  "ln_invoice": {
    "invoice": "lnbcrt10u1p33lg..."
  }
}
```

Have `ln2` pay it:

```shell
$ ln2 pay lnbcrt1u1p3vcp...
```

Have mint client check that payment succeeded, fetch notes, and display new balances:

```shell
$ fedimint-cli wait-invoice lnbcrt1u1p3vcp...
$ fedimint-cli fetch
$ fedimint-cli info
```

Read [more about the Gateway here](./gateway.md)

### Other options

There also exist some other, more experimental commands that can be explored using the `--help` flag:

```shell
$ fedimint-cli help

fedimint-cli 

USAGE:
    fedimint-cli --workdir <WORKDIR> <SUBCOMMAND>

ARGS:
    <WORKDIR>    

OPTIONS:
    -h, --help    Print help information

SUBCOMMANDS:
    connect-info      Config enabling client to establish websocket connection to federation
    fetch             Fetch (re-)issued notes and finalize issuance process
    help              Print this message or the help of the given subcommand(s)
    info              Display wallet info (holdings, tiers)
    join-federation   Join a federation using it's ConnectInfo
    ln-invoice        Create a lightning invoice to receive payment via gateway
    ln-pay            Pay a lightning invoice via a gateway
    peg-in            Issue notes in exchange for a peg-in proof (not yet implemented, just
                          creates notes)
    peg-in-address    Generate a new peg-in address, funds sent to it can later be claimed
    peg-out           Withdraw funds from the federation
    reissue           Reissue notes received from a third party to avoid double spends
    spend             Prepare notes to send to a third party as a payment
    validate          Validate tokens without claiming them (only checks if signatures valid,
                          does not check if nonce unspent)
    wait-block-height Wait for the fed to reach a consensus block height
    wait-invoice      Wait for incoming invoice to be paid
```
