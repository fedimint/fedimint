# Minimint

This is an experimental implementation of a federated chaumian bank.

## Running it locally
### Generating config
You first need to generate some config. All scripts assume config to be located in a folder called `cfg`. Then you can
generate the necessary configuration files as follows:

```
mkdir -p cfg
cargo run --example configgen cfg <num_nodes> 5000 6000 
```

`<num_nodse` is the amount of nodes the federation shall consist of. It should be >=4 (I always test with 5) and not too big as the
cryptography of the BFT protocol is rather intense and you should ideally have 1 core per node. The numbers `5000` and
`6000` specify the beginning of the port range the inner-federation sockets and API sockets bind to.

### Running the mints
A script for running all mints at once is provided at `scripts/startfed.sh`. Run it as follows:

```
./scripts/startfed.sh <num_nodes> 0
```

The `0` in the end specifies how many nodes to leave out. E.g. changing it to one would skip the first node. This is
useful to run a single node with a debugger attached.

Log output can be adjusted using the `RUST_LOG` environment variable and is set to `info` by default.

### Testing issuance with the client
To make the mint actually do something you can run the example client which will first request the issuance of `<amt>`
coins and the a reissuance of said coins, verifying that it receives valid coins at every step.

```
cargo run --example client cfg/client.json <amt>
```