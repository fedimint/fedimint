# Integration Testing
The Rust integration tests allow developers to test the interactions between the Minimint Federation, LN gateway, Clients, Lightning and Bitcoin.

Note there is also a shell-based integration test in `scripts/integrationtest.sh` that will run the integration tests and some additional CLI-based tests prior to PRs being merged.

## Writing tests
Tests cases begin by initializing test fixtures with the number of federation nodes, the threshold that can misbehave, and the coin denomination tiers:

```rust
let (fed, user, bitcoin, gateway, ln) = fixtures(2, 0, &[sats(100), sats(1000)]).await;
```

Initialization will spawn API and HBBFT consensus threads for federation nodes starting at port `4000` then give you access to the following:
- `fed`- control and inspect federation nodes and consensus
- `user`- calls functions in the user client API to simulate minimint users
- `bitcoin`- manipulate the shared Bitcoin network
- `gateway`- calls functions in the gateway client API to simulate a gateway node
- `lightning`- manipulate the gateway LN node and another connected LN node

Calling functions on the clients can send requests to the federation's API and add new proposals to consensus:
```rust
user.client.peg_in(proof, tx, rng()).await.unwrap();
```
In order to simulate consensus we have to tell the federation how many epochs to run:
```rust
fed.run_consensus_epochs(2).await;
```
Note that because HBBFT and consensus processing are concurrent you must always add an additional epoch to consume a `ConsensusOutcome` before any newly proposed `ConsensusItems` will be processed.

## Running tests
Tests run by default with fake Lightning and Bitcoin services for fast concurrent testing that succeeds in any environment, but can also be run against real services.

To run the tests in parallel against fake versions of Lightning and Bitcoin:
```shell
export MINIMINT_TEST_REAL=0
cargo test -p minimint
```

When integration tests run they will output a debug log for each epoch:

```
- Epoch: 1 -
  Peer 0: Wallet Block Height 10863
  Peer 1: Wallet Block Height 10863

- Epoch: 2 -
  Peer 0: Transaction
    Input: Wallet PegIn with TxId 49af58a2
    Output: Mint Coins 4500000 msat
...
- Epoch: 12 -
  Peer 0: Wallet Peg Out PSBT 94344c75 with 0 signatures
  Peer 1: Wallet Peg Out PSBT 94344c75 with 0 signatures

- Epoch: 13 -
  Peer 0: Wallet Peg Out PSBT 94344c75 with 1 signatures
  Peer 1: Wallet Peg Out PSBT 94344c75 with 1 signatures
```
which can be very useful for debugging what the minimint consensus is doing.
You may wish to add the `--test-threads=1` flag or add `#[ignore]` to tests to prevent concurrent debug output.

## Running with real services
Make sure you've [installed](https://github.com/ElementsProject/lightning#installation) bitcoind and lightningd.
Then you can run the following commands to start the services:
```shell
mkdir -p it/bitcoin
bitcoind -regtest -fallbackfee=0.00001 -txindex -server -rpcuser=bitcoin -rpcpassword=bitcoin -datadir=it/bitcoin &

# Wait for bitcoin to start before running Lightning
until [ "$(bitcoin-cli -regtest -rpcuser=bitcoin -rpcpassword=bitcoin getblockchaininfo | jq -r '.chain')" == "regtest" ]; do
  sleep 1
done

lightningd --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=it/ln1 --addr=127.0.0.1:9000 &
lightningd --network regtest --bitcoin-rpcuser=bitcoin --bitcoin-rpcpassword=bitcoin --lightning-dir=it/ln2 --addr=127.0.0.1:9001 &
```

You can now run the integration tests against real instances of Bitcoin and Lightning nodes, using one thread to avoid concurrency issues:

```shell
export MINIMINT_TEST_REAL=1
export MINIMINT_TEST_DIR=$PWD/it/
cargo test -p minimint -- --test-threads=1
```

The first time the tests run it will take several seconds for the LN gateway to fund a channel.
Subsequent tests should start up relatively fast.

If you wish to clean-up the services you can run:
```shell
killall bitcoind
killall lightningd
rm -rf it
```
