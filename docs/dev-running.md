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

![screenshot of the federation running in tmux](tmuxinator.png)

### Using the client

Note as you run commands the mint nodes will output logging information which you can adjust by setting the [RUST_LOG](https://docs.rs/env_logger/latest/env_logger/) env variable.

The previous step has already set up an e-cash client with a funded wallet for you. If you are interested in the details take a look at [`scripts/pegin.sh`](../scripts/pegin.sh).

You can view your client's holdings using the `info` command:

```shell
$ mint-client-cli info

We own 18 coins with a total value of 99000000 msat
We own 9 coins of denomination 1000000 msat
We own 9 coins of denomination 10000000 msat
```

The `spend` subcommand allows sending tokens to another client. This will select the smallest possible set of the client's coins that represents a given amount. The coins are base64 encoded and printed to stdout.

```shell
$ mint-client-cli spend 400000

AQAAAAAAAABAQg8AAA...
```

The `validate` subcommand checks the validity of the signatures without claiming the tokens. It does not check if the nonce is unspent.

```shell
$ mint-client-cli validate AQAAAAAAAABAQg8AAA...

All tokens have valid signatures
```

A receiving client can now reissue these coins to claim them and avoid double spends:

```shell
$ mint-client-cli reissue AQAAAAAAAABAQg8AAA...
$ mint-client-cli fetch

Fetched coins issuance=5b1ac4e9604...
```

### Using the gateway

First let's have the gateway execute a peg-in so it has an ecash token balance. We can use the same `pegin.sh` script as before, but add an extra parameter to tell it to use the gateway:

```shell
$ ./scripts/pegin.sh 10000 1
```

Now we can use `lightning-cli` of the node where the gateway plugin is running to get our ecash token balance:

```shell
$ ln1 gw-balance
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
$ mint-client-cli ln-pay "lnbcrt1u1p3vdl3ds..."
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
$ mint-client-cli ln-invoice 1000 "description"
lnbcrt1u1p3vcp...
```

Have `ln2` pay it:

```shell
$ ln2 pay lnbcrt1u1p3vcp...
```

Have mint client check that payment succeeded, fetch coins, and display new balances:

```shell
$ mint-client-cli wait-invoice lnbcrt1u1p3vcp...
$ mint-client-cli fetch
$ mint-client-cli info
```

### Other options

There also exist some other, more experimental commands that can be explored using the `--help` flag:

```shell
$ mint-client-cli help

mint-client-cli 

USAGE:
    mint-client-cli <WORKDIR> <SUBCOMMAND>

ARGS:
    <WORKDIR>    

OPTIONS:
    -h, --help    Print help information

SUBCOMMANDS:
    connect-info      Config enabling client to establish websocket connection to federation
    fetch             Fetch (re-)issued coins and finalize issuance process
    help              Print this message or the help of the given subcommand(s)
    info              Display wallet info (holdings, tiers)
    join-federation   Join a federation using it's ConnectInfo
    ln-invoice        Create a lightning invoice to receive payment via gateway
    ln-pay            Pay a lightning invoice via a gateway
    peg-in            Issue tokens in exchange for a peg-in proof (not yet implemented, just
                          creates coins)
    peg-in-address    Generate a new peg-in address, funds sent to it can later be claimed
    peg-out           Withdraw funds from the federation
    reissue           Reissue tokens received from a third party to avoid double spends
    spend             Prepare coins to send to a third party as a payment
    validate          Validate tokens without claiming them (only checks if signatures valid,
                          does not check if nonce unspent)
    wait-block-height Wait for the fed to reach a consensus block height
    wait-invoice      Wait for incoming invoice to be paid
```
