# MiniMint

MiniMint is a federated [Chaumian e-cash](https://en.wikipedia.org/wiki/Ecash) mint backed by bitcoin with deposits and withdrawals that can occur on-chain or via Lightning.

**DO NOT USE IT WITH REAL MONEY, THERE ARE MULTIPLE KNOWN SECURITY ISSUES.**

## Getting involved

If you want to learn more about the general idea go to [fedimint.org](https://fedimint.org/), beyond a high level explanation you can also find links to talks and blog posts at the bottom of the page.

Visit our [Discord channels](https://discord.gg/JEdvZ8fv) to discuss general questions, development issues, and specific integrations.

To get started with development have a look at the:
* [GitHub Issues](https://github.com/fedimint/minimint/issues): things to fix, planned features, longer term architectural choices, etc.
* [Architecture](docs/architecture.md) - high-level description of the codebase and design
* [Integration tests](integrationtests/README.md) - instructions on how to write and run the integration tests
* [Scripts](scripts/README.md) - useful scripts for running the tests and federation

PRs fixing TODOs or issues are always welcome, but please discuss more involved changes in an issue first. Smaller PRs to fix typos, broken links etc. are also very welcome.
Happy hacking!

## Running MiniMint
MiniMint consists of three kinds of executables:
* **Federation nodes** - servers who form the mint by running a consensus protocol
* **Lightning gateways** - allows users send and receive over Lightning by bridging between the mint and an LN node
* **User clients** - handles user communication with the mint and the gateway

### Prerequisites
In order to run MiniMint you will need:
- The [Rust toolchain](https://www.rust-lang.org/tools/install) to build and run the executables
- The [Nix package manager](https://nixos.org/download.html) for managing build and test dependencies

Clone and `cd` into the MiniMint repo:
```shell
git clone git@github.com:fedimint/minimint.git
cd minimint
```

### Building and Configuring
First we need to build the executables, set env vars, and generate mint configs within the Nix environment (takes a few minutes the first time):
```shell
nix-shell
source ./scripts/build.sh [fed_size] [dir]
```
with optional parameters:
* **`fed_size`:** number of federation nodes to run (default=`4`)
* **`dir`:** a directory to store the databases and config files (default=`mktemp -d`)

### Running
In order to test locally we need Bitcoin running in [RegTest mode](https://developer.bitcoin.org/examples/testing.html#regtest-mode) (still within `nix-shell`):

```shell
source ./scripts/setup-tests.sh
```
This starts `bitcoind` and 2 instances of `lightningd` with a channel between them for testing Lightning.

Now we can start the federation with:
```shell
bash ./scripts/start-fed.sh
```
The federation will connect to your local Bitcoin node and bind to ports starting at `127.0.0.1:5000` listening for clients to submit transactions.

If you wish to run the Lightning gateway to test sending and receiving over the Lightning network run:
```shell
bash ./scripts/start-gateway.sh
```

In order to clean-up these processes you can either `exit` the shell or run `kill_minimint_processes`.

### Using the client
Note as you run commands the mint nodes will output logging information which you can adjust by setting the [RUST_LOG](https://docs.rs/env_logger/latest/env_logger/) env variable.

Use the peg-in script to mine some bitcoin and deposit funds in exchange for e-cash.
```shell
bash ./scripts/pegin.sh 0.0001
```
You can adjust the amount of bitcoin to peg-in with, but avoid large amounts as this may take a very long time.

You can view your client's holdings using the `info` command:

```shell
$ mint_client info

INFO mint_client_cli: We own 18 coins with a total value of 99000000 msat
INFO mint_client_cli: We own 9 coins of denomination 1000000 msat
INFO mint_client_cli: We own 9 coins of denomination 10000000 msat
```

The `spend` subcommand allows sending tokens to another client. This will select the smallest possible set of the client's coins that represents a given amount. The coins are base64 encoded and printed to stdout.

```shell
$ mint_client spend 400000

AQAAAAAAAABAQg8AAA...
```

A receiving client can now reissue these coins to claim them and avoid double spends:

```shell
$ mint_client reissue AQAAAAAAAABAQg8AAA...
$ mint_client fetch

INFO mint_client_cli: Fetched coins issuance=5b1ac4e9604...
```

### Using the gateway

Generate a Lightning invoice from LN2, our non-gateway lightning node:

```shell
$ ln2 invoice 100000 test test 1m

{
   "bolt11": "lnbcrt1u1p3vdl3ds...",
   ...
}
```

Pay the invoice by copying the `bolt11` invoice field:

```shell
$ mint_client ln-pay "lnbcrt1u1p3vdl3ds..."
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


### Other options

There also exist some other, more experimental commands that can be explored using the `--help` flag:

```shell
$ mint_client help

mint-client-cli 

USAGE:
    mint-client-cli <WORKDIR> <SUBCOMMAND>

ARGS:
    <WORKDIR>    

OPTIONS:
    -h, --help    Print help information

SUBCOMMANDS:
    fetch             Fetch (re-)issued coins and finalize issuance process
    help              Print this message or the help of the given subcommand(s)
    info              Display wallet info (holdings, tiers)
    ln-pay            Pay a lightning invoice via a gateway
    peg-in            Issue tokens in exchange for a peg-in proof (not yet implemented, just
                          creates coins)
    peg-in-address    Generate a new peg-in address, funds sent to it can later be claimed
    peg-out           Withdraw funds from the federation
    reissue           Reissue tokens received from a third party to avoid double spends
    spend             Prepare coins to send to a third party as a payment

```
