# Fedimint Lightning Gateways

Lightning gateways provide routing services into and out of Fedimint Federations. In essence, a gateway is a specialized Fedimint client paired up with a lightning node, so it can route payments on behalf of users in the Federation.

A single gateway can serve multiple Federations.

---

## Lightning Backends

The gateway currently supports three different lightning backends:

* Internal Node (powered by [Lightning Development Kit](https://github.com/lightningdevkit/ldk-node))
* [Core Lightning (CLN)](https://github.com/ElementsProject/lightning)
* [Lightning Network Daemon (LND)](https://github.com/lightningnetwork/lnd)

The first option is great if you want to run a gateway without having to manage a separate lightning node or manage liquidity. We plan on automating liquidity management for this backend using the [Lightning Service Provider (LSP) spec](https://github.com/BitcoinAndLightningLayerSpecs/lsp) and channel splicing to allow for gateway operators to choose an LSP, insert funds, and let the gateway handle the rest. However, since the channel and liquidity management are automated, this backend is not well-suited as a routing node.

The second two options are great if you are already running a lightning node, since you can use your existing liquidity for routing Fedimint payments. They are also preferable if you intend to run a lightning routing node in addition to routing Fedimint payments.

## Components

A Fedimint lightning gateway consists of the following components:

### Gatewayd

A webserver daemon that runs all the business logic of a gateway. Think of this as "The Gateway".

- Given a single gateway can serve multiple Federations at the same time, gatewayd operates over an abstraction called a gateway actor.
- A **Gateway Actor** contains one (and only one) client to a Federation which the gateway serves.
- The gateway will have as many gateway actors as the number of Federations it serves, coordinating these gateway actors where necessary in order to route payments between such federations.

<details>
  <summary>Details on Lightning <-> E-Cash Contracting</summary>
  Just like other Federation clients, the client within the gateway actor interfaces with the Federation through a well-defined **FederationAPI**

  - To receive incoming lightning payments, the client within a gateway actor calls to **FederationAPI**s to complete certain incoming contract functions
  - To make outgoing lightning payments, clients within a federation served by the gateway will use gatewayd `pay_invoice` API.

  Read more about the gateway <-> federation interactions and contracts [here](../modules/fedimint-ln-common/src/contracts/mod.rs).
</details>

### Gateway-lnrpc-extension

A Lightning extension / plugin service that provides all the necessary Lightning functionalities the gateway webserver daemon.

- Specification for such an extension and how it interfaces with **gatewayd** is defined in [gateway_lnrpc.proto](../gateway/ln-gateway/proto/gateway_lnrpc.proto) gRPC spec. Read more about gRPC [here](https://grpc.io/docs/what-is-grpc/introduction/).
- The extension usually runs alongside a lightning node, or within the node as a plugin! It works specifically for that lightning node implementation
  - We have implemented [gateway-cln-extension](../gateway/ln-gateway/src/bin/cln_extension.rs) that works with for CLN nodes
  - **TODO:** help us implement a similar extension for [Eclair](https://github.com/ACINQ/eclair) nodes
  - **TODO:** help us implement a similar extension for _your-favorite-variant_ lightning node

---

## Managing your Gateway

As a gateway owner/operator, there are two options available for managing your gateway:

### gateway-cli

An intuitive CLI tool for interacting with **gatewayd**. Run `gateway-cli help` to see some of the commands available in managing the gateway:

```shell
$ gateway-cli help

Usage: gateway-cli [OPTIONS] <COMMAND>

Commands:
  version-hash               Display CLI version hash
  info                       Display high-level information about the gateway
  balance                    Check gateway balance
  address                    Generate a new peg-in address, funds sent to it can later be claimed
  deposit                    Deposit funds into a gateway federation
  withdraw                   Claim funds from a gateway federation
  connect-fed                Connect federation with the gateway
  help                       Print this message or the help of the given subcommand(s)
  lightning
    get-funding-address      Generate a new address belonging to the on-chain wallet of the gateway\'s underlying lightning node
    open-channel             Open a lightning channel to another lightning node from the gateway\'s underlying lightning node
    list-active-channels     List all channels on the underlying lightning node that can send or receive payments
    close-channels-with-peer Close all lightning channels with a given peer, claiming the funds to the lightning node\'s on-chain wallet
    wait-for-chain-sync      Wait for the gateway\'s underlying lightning node to sync to the blockchain at a given height

Options:
  -a, --address <ADDRESS>          The address of the gateway webserver [default: http://127.0.0.1:8175]
      --rpcpassword <RPCPASSWORD>  WARNING: Passing in a password from the command line may be less secure!
  -h, --help                       Print help information
  -V, --version                    Print version information
```

<details>
  <summary>Joining a Federation using the CLI</summary>
  This section outlines how to add a gateway to a federation and fund it through a peg-in.

  A peg-in sends on-chain funds to the federation in exchange for e-cash. A gateway must have a balance of e-cash in a particular federation to be able to facilitate lightning payments into that federation. This is because an inbound payment involves the gateway giving up some of its e-cash in exchange for receiving a lightning payment of the same or greater size.

  1. Connect the Gateway to a Federation
  Start by connecting your gateway to the desired federation using the following command:
  ```bash
  $ gateway-cli connect-fed <federation-invite-code>
  ```

  2. Requesting a Federation Peg-In Address
  Once the gateway is successfully integrated into the federation, you can request a new address to deposit coins into the federation in exchange for e-cash for the federation:
  ```bash
  $ gateway-cli address --federation-id <federation-id>
  "bc1asd..."
  ```
  **Note:** You can obtain the `<federation-id>` by calling `gateway-cli info` after joining the federation.

  3. Send Coins to the Gateway
  After obtaining the deposit address, you can send coins to this address. Below is an example using `lncli` to send 50,000 satoshis (sats), but you can use any compatible method:
  ```bash
  $ lncli sendcoins <gateway-btc-address> 50000 --min_confs 0 --sat_per_vbyte <sats-per-vbyte>
  { "txid": "1a6..." }
  ```
  **Note:** Replace `<gateway-btc-address>` with the bitcoin address you generated previously for the gateway. Additionally, ensure you check the current transaction fees in the mempool to determine an appropriate value for `<sats-per-vbyte>` to ensure timely confirmation of your transaction.

  4. Confirm the Transaction
  To ensure the security of the transaction, verify that it has received at least `finality_delay + 1` confirmations from the Bitcoin network. The `finality_delay` parameter is defined in the federation's configuration settings.

  Once the transaction has achieved the required number of confirmations, the funds will be available in the gateway.
  ```bash
  $ gateway-cli info
  {
    "version_hash": "...",
    "federations": [
      {
        "federation_id": "...",
        "balance_msat": 50000000,
        "config": {
          ...
        }
      }
    ]
  }
  ```
  This process ensures that your gateway is properly funded and ready to participate in the federation's activities.
</details>

<details>
  <summary>Leaving a Federation using the CLI</summary>
  This section provides a detailed guide on how to withdraw (or peg-out) the gateway's funds within a federation and subsequently remove the gateway from that federation.

  1. Obtain a Withdrawal Address
  First, generate a new address to which the funds will be withdrawn. Below is an example using `lncli` to create a new address:
  ```bash
  $ lncli newaddress p2tr
  { "address": "bc1xas..." }
  ```

  2. Withdraw Funds
  To initiate the withdrawal of funds to a specified address, use the following command:
  ```bash
  $ gateway-cli withdraw --federation-id <federation-id> --amount 50000 --address bc1xas...
  ```
  **Note:** The amount is specified in satoshis (sats).

  After executing the command, wait for the transaction to be fully processed and confirmed on the network. This ensures that the funds are securely transferred to the designated address.

  3. Removing the Gateway from the Federation
  Once the funds have been successfully withdrawn, you can proceed to remove the gateway from the federation. Execute the following command to tell the gateway to leave the federation:
  ```bash
  $ gateway-cli leave-fed --federation-id <federation-id>
  ```
  This process ensures that the gateway is cleanly removed from the federation after the funds have been securely withdrawn.
</details>

### Mintgate

A simple and delightful dashboard for administrative access and control of your gateway. Presently, Mintgate supports admin functions like:

- Connecting new federations to the gateway
- Depositing funds into connected federations
- Withdrawing funds from federations

---

## Developing the Gateway

As described in [Running Fedimint for dev testing](./tutorial.md#using-the-gateway), running `just mprocs` starts a local development Federation instance with a running gateway instance attached. You can interact with this gateway via `gateway-cli`.

### Developing gateway-lnrpc-extension

- See and contribute to [gateway-cln-extension](../gateway/ln-gateway/src/bin/cln_extension.rs)
- Help add support to other node implementations by building [gateway-lnrpc-extensions](#gateway-lnrpc-extension) for them. You can parent your brand-new extension in this directory, or in your own repository and we will link to it in this open documentation
- Contributions are highly welcome!

## Deploying a Gateway in Production

### Deploy a gateway-lnrpc-extension

- [gateway-cln-extension](../gateway/ln-gateway/src/bin/cln_extension.rs): **TODO:** Add docs here
- other _gateway-lnrpc-extension_: **TODO:** Add docs here

### Configure and deploy gatewayd

- **TODO:** Add docs here

### Provisioning liquidity for a Lightning Gateway

- **TODO:** Add docs here

### Register and Serve Federations

- **TODO:** Add docs here
