# Integration Testing
The Rust integration tests allow developers to test the interactions between the Fedimint Federation, LN gateway, Clients, Lightning and Bitcoin.

[Scripts](../scripts/README.md) exist for running the integration tests manually or as part of GitHub actions.

## Writing tests
Tests cases begin by initializing test fixtures with the number of federation nodes and the coin denomination tiers:

```rust
let (fed, user, bitcoin, gateway, ln) = fixtures(2, &[sats(100), sats(1000)]).await;
```

Initialization will spawn API and HBBFT consensus threads for federation nodes starting at port `4000` then give you access to the following:
- `fed`- control and inspect federation nodes and consensus
- `user`- calls functions in the user client API to simulate fedimint users
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

## Running tests
Tests run by default with fake Lightning and Bitcoin services for fast concurrent testing that succeeds in any environment, but can also be run against real services.

To run the tests in parallel against fake versions of Lightning and Bitcoin:
```shell
export FM_TEST_DISABLE_MOCKS=0
cargo test -p fedimint-tests
```

When integration tests run they will output a debug log for each epoch:

```
- Epoch: 1 -
  Peer 0: Transaction
    Input: Wallet PegIn with TxId dd482519fcb1955732cbf55e730e65d6f9987e758f5a19a754732b595705a3fc
    Output: Mint Coins 5000000 msat

- Balance Sheet -
      -5000.000|IssuanceTotal
         +0.000|RedemptionTotal
      +5000.000|UTXOKey(OutPoint { txid: dd482519fcb1955732cbf55e730e65d6f9987e758f5a19a754732b595705a3fc, vout: 1 })
         +0.000|Total sats
```
which can be very useful for debugging what the fedimint consensus is doing.
You may wish to run `cargo test -p fedimint-tests <test-name>` to prevent concurrent debug output.

## Running with real services
Make sure you've [installed](https://nixos.org/manual/nix/stable/quick-start.html) Nix in order to run the correct versions of bitcoind and lightningd.
Then you can run the following commands to start the services:
```shell
nix develop
source ./scripts/setup-tests.sh
```

You can now run the integration tests against real instances of Bitcoin and Lightning nodes, using one thread to avoid concurrency issues:

```shell
export FM_TEST_DISABLE_MOCKS=1
cargo test -p fedimint-tests -- --test-threads=1
```

If you wish to clean-up the services run:
```shell
kill_fedimint_processes
```
