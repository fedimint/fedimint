# Fedimint Lightning Gateways

Lightning gateways provide routing services in and out of Fedimint Federations. In essence, a gateway is a specialized Fedimint client, paired up with a running instance of lightning node, like [Core Lightning (CLN)](https://github.com/ElementsProject/lightning) or [Lightning Network Daemon (LND)](https://github.com/lightningnetwork/lnd), so it can route payments on behalf of the Federation.

A single Gateway can serve multiple Federations.

---

## Components

A Fedimint lightning gateway consists of the following components:

### Gatewayd

A webserver daemon that runs all the business logic of a gateway. Think of this as "The Gateway".

- Given a single gateway can serve multiple Federations at the same time, gatewayd operates over an abstraction named gateway actor.
- A **GatewayActor** contains one (and only one) client to a Federation which the gateway serves.
- The gateway will have as many actors as the number of Federations it serves, coordinating these actors where necessary in order to route payments between such federations.

> **Additional Notes:**
>
> Just like other Federation clients, the client within the gateway actor interfaces with the Federation through a well-defined **FederationAPI**
>
> - To receive incoming lightning payments, the client within a gateway actor calls to **FederationAPI**s to complete certain incoming contract functions
> - To make outgoing lightning payments, clients within a federation served by the gateway will use gatewayd `pay_invoice` API.
>
> Read [more about the gateway <-> federation interactions and contracts](../modules/fedimint-ln-common/src/contracts/mod.rs) here

### Gateway-lnrpc-extension

A Lightning extension / plugin service that provides all the necessary Lightning functionalities the gateway webserver daemon.

- Specification for such an extension and how it interfaces with **gatewayd** is defined in [gateway_lnrpc.proto](../gateway/ln-gateway/proto/gateway_lnrpc.proto) gRPC spec. [Read more about gRPCs here](https://grpc.io/docs/what-is-grpc/introduction/).
- The extension usually runs alongside a lightning node, or within the node as a plugin! It works specifically for that lightning node implementation
  - We have implemented [gateway-cln-extension](../gateway/ln-gateway/src/bin/cln_extension.rs) that works with for CLN nodes
  - **TODO:** help us implement a similar extension for [LND](https://github.com/lightningnetwork/lnd) nodes
  - **TODO:** help us implement a similar extension for [Eclair](https://github.com/ACINQ/eclair) nodes
  - **TODO:** help us implement a similar extension for [LDK](https://github.com/lightningdevkit/ldk-node) nodes
  - **TODO:** help us implement a similar extension for [Sensei](https://github.com/L2-Technology/sensei) nodes
  - **TODO:** help us implement a similar extension for _your-favorite-variant_ lightning node

---

## Interacting with the Gateway

When you have a running instance of Fedimint gateways, there are two options available for administering the gateway:

### gateway-cli

An intuitive CLI tool for interacting with **gatewayd**. Run `gateway-cli help` to see some of the commands available in managing the gateway:

```shell
$ gateway-cli help

Usage: gateway-cli [OPTIONS] <COMMAND>

Commands:
  version-hash               Display CLI version hash
  info                       Display high-level information about the Gateway
  balance                    Check gateway balance
  address                    Generate a new peg-in address, funds sent to it can later be claimed
  deposit                    Deposit funds into a gateway federation
  withdraw                   Claim funds from a gateway federation
  connect-fed                Connect federation with the gateway
  help                       Print this message or the help of the given subcommand(s)
  lightning
    get-funding-address      Generate a new address belonging to the on-chain wallet of the gateway\'s underlying lightning node
    open-channel             Open a lightning channel to another lighting node from the gateway\'s underlying lightning node
    list-active-channels     List all channels on the underlying lightning node that can send or receive payments
    close-channels-with-peer Close all lightning channels with a given peer, claiming the funds to the lightning node\'s on-chain wallet
    wait-for-chain-sync      Wait for the gateway\'s underlying lightning node to sync to the blockchain at a given height

Options:
  -a, --address <ADDRESS>          The address of the gateway webserver [default: http://127.0.0.1:8175]
      --rpcpassword <RPCPASSWORD>  WARNING: Passing in a password from the command line may be less secure!
  -h, --help                       Print help information
  -V, --version                    Print version information
```

#### Gateway Peg-in Process
This section outlines the steps to add a gateway to a federation and subsequently fund the gateway.

##### Connecting the Gateway to a Federation

Start by connecting your gateway to the desired federation using the following command:
```bash
$ gateway-cli connect-fed <federation-invite-code>
```

##### Requesting a Deposit Address
Once the gateway is successfully integrated into the federation, you can request a new address to deposit coins:
```bash
$ gateway-cli address --federation-id <federation-id>
"bc1asd..."
```
**Note:** You can obtain the `<federation-id>` by calling `gateway-cli info` after joining the federation.

##### Sending Coins to the Gateway
After obtaining the deposit address, you can send coins to this address. Below is an example using `lncli` to send 50,000 satoshis (sats), but you can use any compatible method:
```bash
$ lncli sendcoins <gateway-btc-address> 50000 --min_confs 0 --sat_per_vbyte <sats-per-vbyte>
{ "txid": "1a6..." }
```
**Note:** Replace `<gateway-btc-address>` with the bitcoin address you generated previously for the gateway. Additionally, ensure you check the current transaction fees in the mempool to determine an appropriate value for `<sats-per-vbyte>` to ensure timely confirmation of your transaction.

##### Confirming the Transaction
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

#### Gateway Peg-out Process
This section provides a detailed guide on how to withdraw funds from the gateway and subsequently remove the gateway from a federation.

##### Obtaining a Withdrawal Address
First, generate a new address to which the funds will be withdrawn. Below is an example using `lncli` to create a new address:
```bash
$ lncli newaddress p2tr
{ "address": "bc1xas..." }
```
##### Withdrawing Funds
To initiate the withdrawal of funds to a specified address, use the following command:
```bash
$ gateway-cli withdraw --federation-id <federation-id> --amount 50000 --address bc1xas...
```
**Note:** The amount is specified in satoshis (sats).

After executing the command, wait for the transaction to be fully processed and confirmed on the network. This ensures that the funds are securely transferred to the designated address.

##### Removing the Gateway from the Federation
Once the funds have been successfully withdrawn, you can proceed to remove the gateway from the federation. Execute the following command to make the gateway leave the federation:
```bash
$ gateway-cli leave-fed --federation-id <federation-id>
```
This process ensures that the gateway is cleanly removed from the federation after the funds have been securely withdrawn.


### Mintgate

A simple and delightful dashboard for administrative access and control of your Fedimint gateway. Presently, Mintgate supports admin functions like:

- Connecting new federations to the gateway
- Depositing funds into a connected federation
- Withdrawing funds from the federations

---

## Developing the Gateway

As described in [Running Fedimint for dev testing](./tutorial.md#using-the-gateway), running `just mprocs` starts a local development Federation instance with a running Gateway instance attached. You can interact with this Gateway via `gateway-cli`.

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
