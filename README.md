# Minimint

This is an experimental implementation of a federated chaumian bank.

## Running it locally
I'm currently using rust `rustc 1.54.0-nightly (ca82264ec 2021-05-09)` for development. I'll try to keep it up to date
and eventually get off nightly.

### Generating config
You first need to generate some config. All scripts assume config to be located in a folder called `cfg`. Then you can
generate the necessary configuration files as follows:

```shell
mkdir -p cfg
cargo run --example configgen cfg <num_nodes> 5000 6000 <tier1> <tier2> …
```

`<num_nodse` is the amount of nodes the federation shall consist of. It should be >=4 (I always test with 5) and not too big as the
cryptography of the BFT protocol is rather intense and you should ideally have 1 core per node. The numbers `5000` and
`6000` specify the beginning of the port range the inner-federation sockets and API sockets bind to. The remaining
arguments will be interpreted as amount tiers in msat.

This will both create all the `server-n.json` config files and one `client.json`. If you want to play with multiple
clients you should create ons subdirectory per client and copy the `client.json` into each.

### Running the mints
A script for running all mints and a regtest `bitcoind` at once is provided at `scripts/startfed.sh`. Run it as follows:

```shell
bash scripts/startfed.sh <num_nodes> 0
```

The `0` in the end specifies how many nodes to leave out. E.g. changing it to one would skip the first node. This is
useful to run a single node with a debugger attached.

Log output can be adjusted using the `RUST_LOG` environment variable and is set to `info` by default. Logging can be
adjusted per module, see the [`env_logger` documentation](https://docs.rs/env_logger/0.8.4/env_logger/#enabling-logging)
for details.

### Using the client
First you need to make sure that your regtest `bitcoind` has some coins that are mature. For that you can generate a
few hundred blocks to your own wallet:

```shell
ADDRESS="$(bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin getnewaddress)"
bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin generatetoaddress 200 "$ADDRESS"
```

the you can use the peg-in script to deposit funds. It contains comments that explain the deposit process.

```shell
bash scripts/pegin.sh <amount in BTC>
```

Take care to not request too big of a peg-in (depending on your amount tier the smallest representations as tokens might
be too big to finish signing in reasonable time) or too small (there is a 500sat fee that needs to be paid). After about
20s your default client in `cfg` should have newly issued coins.

You can view your client's holdings using the `info` command:

```
minimint $ cargo run --bin mint-client --release -- cfg info
    Finished release [optimized] target(s) in 0.11s
     Running `target/release/mint-client cfg info`
Jun 15 14:57:22.066  INFO mint_client: We own 14 coins with a total value of 9500000 msat
Jun 15 14:57:22.066  INFO mint_client: We own 5 coins of denomination 100000 msat
Jun 15 14:57:22.066  INFO mint_client: We own 9 coins of denomination 1000000 msat
```

The `spend` subcommand allows to send tokens to another client. This will select the smallest possible set of the
client's coins that represents a given amount. The coins are base64 encoded and printed to stdout.

```
minimint $ cargo run --bin mint-client --release -- cfg spend 400000
    Finished release [optimized] target(s) in 0.12s
     Running `target/release/mint-client cfg spend 400000`
AQAAAAAAAACghgEAAAAAAAQAAAAAAAAAA7mGus9L4ojsIsctFK7oNz5s4ozZe3pVa0S1jZ3XvSnMMAAAAAAAAACFjOG3a4vlxBOCa9fYD6qWIM2JhH9vitG0
DXQhd9KhGYKheKADLOVXgZwOQDX0NheGP5fFEMYOfidY1FPXB1qRhrEiZKh3YVb2i922uUHoggOsZhrLpk4EGCJjuT1QUWpO8HZ9WOxD4oUv6nPNVQnKvDAA
AAAAAAAAoXKhtm/0w8pFz7CN6xcEQUnukrNcfhc/NtRita1vvZDyX/NBiSmHZVyWx8WEloclIw0A8ljJhp+b517c1LsLJ5Z6Issf9QcV/hwAgY/RJo4DRGWD
IDyyyBYXxRbFuTZoDaTR3TM/49m41Bl7/CPVz98wAAAAAAAAAJOjsZSwWrBUXt+OsojEkxRbqn8KAJrz1TTQkNrdlEiaSRqjx+YCfET3HwL3j26s2clhRugM
rRj6oMC6wKoZz0jCuS5i8faLRHGZp3AMR1/xAvMglQZ9zMEDdDd7dcxwp9WpR6JfdAUJku3EGQ/FUXaQMAAAAAAAAACUXn9s935ruZ5jA5o5aNf1u/smH4TN
+qO8jMHVf6Zzh22P5jJvhWdX62s7kftXTa9AKeiC0I4QxWdWVK4JTLnE62GzGLQqQyEkne3Pn/Pm1g==
```

A receiving client can now reissue these coins to claim them and avoid double spends:

```
minimint $ cargo run --bin mint-client --release -- cfg reissue AQAAAAAAAACghgE…
    Finished release [optimized] target(s) in 0.13s
     Running `target/release/mint-client cfg reissue AQAAAAAAAACghgE…
Jun 15 15:01:47.027  INFO mint_client: Starting reissuance transaction for 400000 msat
Jun 15 15:01:47.040  INFO mint_client: Started reissuance 47d8f08710423c1e300854ecb6463ca6185e4b3890bbbb90fd1ff70c72e1ed18, please fetch the result later
minimint $ cargo run --bin mint-client --release -- cfg fetch
    Finished release [optimized] target(s) in 0.12s
     Running `target/release/mint-client cfg fetch`
Jun 15 15:02:06.264  INFO mint_client: Fetched coins from issuance 47d8f08710423c1e300854ecb6463ca6185e4b3890bbbb90fd1ff70c72e1ed18
```

There also exist some other, more experimental commands that can be explored using the `--help` flag:

```
minimint $ cargo run --bin mint-client --release -- --help
    Finished release [optimized] target(s) in 0.12s
     Running `target/release/mint-client --help`
mint-client 0.1.0

USAGE:
    mint-client <workdir> <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <workdir>    

SUBCOMMANDS:
    fetch             Fetch (re-)issued coins and finalize issuance process
    help              Prints this message or the help of the given subcommand(s)
    info              Display wallet info (holdings, tiers)
    ln-pay            Pay a lightning invoice via a gateway
    peg-in            Issue tokens in exchange for a peg-in proof (not yet implemented, just creates coins)
    peg-in-address    Generate a new peg-in address, funds sent to it can later be claimed
    peg-out           Withdraw funds from the federation
    reissue           Reissue tokens received from a third party to avoid double spends
    spend             Prepare coins to send to a third party as a payment
```