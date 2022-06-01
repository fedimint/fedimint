# Minimint

**This is an experimental implementation of a federated Chaumian bank. DO NOT USE IT WITH REAL MONEY, THERE ARE MULTIPLE KNOWN SECURITY ISSUES.**

## Getting involved

If you want to learn more about the general idea go to [fedimint.org](https://fedimint.org/), beyond a high level explanation you can also find links to talks and blog posts at the bottom of the page.

There exist three main communication channels for the project at the moment:
* [FediMint telegram group](https://t.me/fedimint) - high level ideas, questions, cryptography discussions, etc., nothing code related though (to keep it low noise).
* [MiniMint dev telegram group](https://t.me/+uiO1s8gPIBE2YTU0) - code related discussions that aren't a good fit for an issue, getting started, if you have weird compiler errors etc.
* GitHub Issues: Things to fix, planned features, longer term architectural choices, etc. (something you want to remember in a week that would be lost in the noise on telegram)

PRs fixing TODOs or issues are always welcome, it might be a good idea though to discuss more involved changes in an issue first to make sure the chosen approach fits into the bigger picture. Smaller PRs to fix typos, broken links etc. are also very welcome.

To get started with development have a look at the:
* [Architecture](docs/architecture.md) - high-level description of the codebase and design
* [Integration tests](integrationtests/README.md) - instructions on how to write and run the integration tests
* `scripts/final-checks.sh` - checks to run locally before opening a PR
* `scripts/integrationtest.sh` - tests that will run automatically after a PR is opened

Happy hacking!

## Running MiniMint locally

MiniMint is tested and developed using rust `stable`, you can get it through your package manager or from [rustup.rs](https://rustup.rs/). If you use nix/nixos you can refer to our [nix](docs/nix_instructions.md) documentation.

MiniMint consists of three kinds of services:
* federation member nodes (`server` binary) which make up the federation and run the consensus protocol among each other.
* a Lightning gateway (`ln_gateway` binary) which acts as a bridge between the federation and the Lightning network allowing users to pay LN invoices with e-cash tokens.
* user clients (`mint-client-cli` binary) that interact with the federation nodes and the gateway

In the following we will set up all three.

### Generate federation config

You first need to generate some config. All scripts assume config to be located in a folder called `cfg`. Then you can generate the necessary configuration files as follows:

```shell
cargo run --bin configgen cfg <num_nodes> <federation_ports> <api_ports> <tier1> <tier2> …
```

The placeholders can be filled in as follows:
* **`<num_nodes>`:** number of nodes to generate config for. Should be >= 4 and not too big as the cryptography of the BFT protocol is rather intense and you should ideally have 1 core per node.
* **`<federation_ports>`:** base port for federation internal connections. If it is set to 5000 for example and there are 4 nodes they will use ports 5000, 5001, 5002 and 5003.
* **`<api_ports>`:** base port for the federation node API server which user clients connect to. If it is set to 6000 for example and there are 4 nodes they will use ports 6000, 6001, 6002 and 6003.
* **`<tier1> … <tier n>`:** E-cash token denominations/amount tiers in milli sat. There are different token denominations to increase efficiency so that instead of issuing 10 1sat tokens 1 10sat token can be issued. Generally powers of a base are a decent choice, e.g. powers of 10: 1 10 100 1000 10000 100000 1000000 10000000 100000000 1000000000 

An example with concrete parameters could look as follows:
```shell
cargo run --bin configgen cfg 4 5000 6000 1 10 100 1000 10000 100000 1000000 10000000 100000000 1000000000
```

This will both create all the `server-n.json` config files and one `federation_client.json`. The server configs are already complete and can be used to run the nodes. The client config on the other hand needs to be amended with some information about a lightning gateway it can use. For that we run

### Running bitcoind and lightningd

First we build a binary for the "lightning gateway":

```shell
cargo build --release --bin ln_gateway
```

Next you'll need to run `bitcoind` and 2 instances `lightningd` to send and receive via Lightning:

```shell
bitcoind -regtest -fallbackfee=0.0004 -txindex -server -rpcuser=bitcoin -rpcpassword=bitcoin

lightningd --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=ln1 --addr=127.0.0.1:9000 --plugin=$PWD/target/release/ln_gateway --minimint-cfg=$PWD/cfg
lightningd --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=ln2 --addr=127.0.0.1:9001
```

Note that we pass the gateway binary as a ["plugin"](https://lightning.readthedocs.io/PLUGINS.html) to the first instance of Core Lightning, as well as a path to our configuration folder.


### Running the mints

A script for running all mints and a regtest `bitcoind` at once is provided at `scripts/startfed.sh`. Run it as follows:

```shell
bash scripts/startfed.sh <num_nodes> 0
```

The `0` in the end specifies how many nodes to leave out. E.g. changing it to one would skip the first node. This is useful to run a single node with a debugger attached.

Log output can be adjusted using the `RUST_LOG` environment variable and is set to `info` by default. Logging can be adjusted per module, see the [`env_logger` documentation](https://docs.rs/env_logger/0.8.4/env_logger/#enabling-logging) for details.

### Setting up a channel from LN1 to LN2
If you want to pay invoices later, the node (ln1) you've set as a gateway needs to have a channel to the payee node :

First generate a few hundred blocks to you your regtest `bitcoind` wallet to ensure it has mature coins.

```shell
ADDRESS="$(bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin getnewaddress)"
bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin generatetoaddress 200 "$ADDRESS"
```

Send your gateway Ligtning node some funds:

```shell
# Get address from gateway lightning node (we'll call it LN_ADDRESS)
lightning-cli --network regtest --lightning-dir=ln1 newaddr

# Send bitcoin to gateway lightning address, and mine a block to confirm it
bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin sendtoaddress <LN_ADDRESS> 1.0
bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin generatetoaddress 1 $ADDRESS
```

Now you can open a channel:

```shell
# First you have to get the LN2_PUB_KEY ("id" in json)
lightning-cli --network regtest --lightning-dir=ln2 getinfo

# Now you can connect LN1 to LN2
lightning-cli --network regtest --lightning-dir=ln1 connect <LN2_PUB_KEY>@127.0.0.1:9001
lightning-cli --network regtest --lightning-dir=ln1 fundchannel <LN2_PUB_KEY> 0.1btc

# Mine some blocks so the channel becomes active
bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin generatetoaddress 10 $ADDRESS
```

### Using the client

Then you can use the peg-in script to deposit funds. It contains comments that explain the deposit process.

```shell
bash scripts/pegin.sh 0.1
```

Take care to not request too big of a peg-in (depending on your amount tier the smallest representations as tokens might be too big to finish signing in reasonable time) or too small (there is a 500sat fee that needs to be paid). After about 20s your default client in `cfg` should have newly issued coins.

You can view your client's holdings using the `info` command:

```
$ cargo run --bin mint-client-cli --release -- cfg info
    Finished release [optimized] target(s) in 0.11s
     Running `target/release/mint-client-cli cfg info`
We own 41 coins with a total value of 9999500000 msat
We own 5 coins of denomination 100000 msat
We own 9 coins of denomination 1000000 msat
We own 9 coins of denomination 10000000 msat
We own 9 coins of denomination 100000000 msat
We own 9 coins of denomination 1000000000 msat
```

The `spend` subcommand allows to send tokens to another client. This will select the smallest possible set of the client's coins that represents a given amount. The coins are base64 encoded and printed to stdout.

```
$ cargo run --bin mint-client-cli --release -- cfg spend 400000
    Finished release [optimized] target(s) in 0.12s
     Running `target/release/mint-client-cli cfg spend 400000`
AQAAAAAAAACghgEAAAAAAAQAAAAAAAAAA7mGus9L4ojsIsctFK7oNz5s4ozZe3pVa0S1jZ3XvSnMMAAAAAAAAACFjOG3a4vlxBOCa9fYD6qWIM2JhH9vitG0
DXQhd9KhGYKheKADLOVXgZwOQDX0NheGP5fFEMYOfidY1FPXB1qRhrEiZKh3YVb2i922uUHoggOsZhrLpk4EGCJjuT1QUWpO8HZ9WOxD4oUv6nPNVQnKvDAA
AAAAAAAAoXKhtm/0w8pFz7CN6xcEQUnukrNcfhc/NtRita1vvZDyX/NBiSmHZVyWx8WEloclIw0A8ljJhp+b517c1LsLJ5Z6Issf9QcV/hwAgY/RJo4DRGWD
IDyyyBYXxRbFuTZoDaTR3TM/49m41Bl7/CPVz98wAAAAAAAAAJOjsZSwWrBUXt+OsojEkxRbqn8KAJrz1TTQkNrdlEiaSRqjx+YCfET3HwL3j26s2clhRugM
rRj6oMC6wKoZz0jCuS5i8faLRHGZp3AMR1/xAvMglQZ9zMEDdDd7dcxwp9WpR6JfdAUJku3EGQ/FUXaQMAAAAAAAAACUXn9s935ruZ5jA5o5aNf1u/smH4TN
+qO8jMHVf6Zzh22P5jJvhWdX62s7kftXTa9AKeiC0I4QxWdWVK4JTLnE62GzGLQqQyEkne3Pn/Pm1g==
```

A receiving client can now reissue these coins to claim them and avoid double spends:

```
$ cargo run --bin mint-client-cli --release -- cfg reissue AQAAAAAAAACghgE…
    Finished release [optimized] target(s) in 0.13s
     Running `target/release/mint-client-cli cfg reissue AQAAAAAAAACghgE…
Jun 15 15:01:47.027  INFO mint_client_cli: Starting reissuance transaction for 400000 msat
Jun 15 15:01:47.040  INFO mint_client_cli: Started reissuance 47d8f08710423c1e300854ecb6463ca6185e4b3890bbbb90fd1ff70c72e1ed18, please fetch the result later
minimint $ cargo run --bin mint-client-cli --release -- cfg fetch
    Finished release [optimized] target(s) in 0.12s
     Running `target/release/mint-client-cli cfg fetch`
Jun 15 15:02:06.264  INFO mint_client_cli: Fetched coins from issuance 47d8f08710423c1e300854ecb6463ca6185e4b3890bbbb90fd1ff70c72e1ed18
```

### Using the gateway

Generate a Lightning invoice from LN2, our non-gateway lightning node:

```shell
lightning-cli --network regtest --lightning-dir=ln2 invoice 4000000000 test test 10m
```

Have LN2 non-gateway lightning node monitor the payment of this invoice. This command hangs until invoice is paid, so run it in another terminal window. Once paid, it will print out some information.

```shell
lightning-cli --network regtest --lightning-dir=ln2 waitinvoice test
```

Pay the invoice: 

```shell
cargo run --bin mint-client-cli --release -- cfg ln-pay <INVOICE>
```

Generate your own invoice: 

```shell
cargo run --bin mint-client-cli --release -- cfg ln-invoice 10000 "description"
```

Have LN2 pay invoice via the "lightning gateway":

```shell
$ lightning-cli --network regtest --lightning-dir=ln2 pay <INVOICE>
{
   "destination": "03b7e95e0d159ea18371912d3326a306e907306413188c36a263cf415d0a9ceefa",
   "payment_hash": "7057839d006a5c5067c7b271724a626ac0f7958502b9522bcd9beaa0d69c0165",
   "created_at": 1656628023.317,
   "parts": 1,
   "msatoshi": 10000,
   "amount_msat": "10000msat",
   "msatoshi_sent": 10000,
   "amount_sent_msat": "10000msat",
   "payment_preimage": "f038aef6054b7c3577cf93bde4a741a0df942a1e2ca6ed5182084ab68bbd51ae",
   "status": "complete"
}
```

### Other options

There also exist some other, more experimental commands that can be explored using the `--help` flag:

```
minimint $ cargo run --bin mint-client-cli --release -- --help
    Finished release [optimized] target(s) in 0.12s
     Running `target/release/mint-client-cli --help`
mint-client-cli 0.1.0

USAGE:
    mint-client-cli <workdir> <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <workdir>    

SUBCOMMANDS:
    fetch             Fetch (re-)issued coins and finalize issuance process
    help              Prints this message or the help of the given subcommand(s)
    info              Display wallet info (holdings, tiers)
    ln-invoice        Create a lightning invoice to receive payment via gateway
    ln-pay            Pay a lightning invoice via a gateway
    peg-in            Issue tokens in exchange for a peg-in proof (not yet implemented, just creates coins)
    peg-in-address    Generate a new peg-in address, funds sent to it can later be claimed
    peg-out           Withdraw funds from the federation
    reissue           Reissue tokens received from a third party to avoid double spends
    spend             Prepare coins to send to a third party as a payment
```
