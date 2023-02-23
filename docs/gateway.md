# Fedimint Lightning Gateways

Lightning gateways provide routing services in and out of Fedimint Federations. In essence, a gateway is a specialized Fedimint client, paired up with a running instance of lightning node like [Core Lightning (CLN)](https://github.com/ElementsProject/lightning) or [Lightning Network Daemon (LND)](https://github.com/lightningnetwork/lnd), so it can route payments on behalf of the Federation.

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
> Just like other Federation clients, the client within the gateway actor interfaces with the Federation through a well defined **FederationAPI**
>
> - To receive incoming lightning payments, the client within a gateway actor calls to **FederationAPI**s to complete certain incoming contract functions
> - To make outgoing lightning payments, clients within a federation served by the gateway will use gatewayd `pay_invoice` API.
>
> Read [more about the gateway <-> federation interactions and contracts](../modules/fedimint-ln/src/contracts/mod.rs) here

### Gateway-lnrpc-extension

A Lightning extension / plugin service that provides all the necessary Lightning functionalities the gateway webserver daemon.

- Specification for such an extension and how it interfaces with **gatewayd** is defined in [gatewaylnrpc.proto](../gateway/ln-gateway/proto/gatewaylnrpc.proto) gRPC spec. [Read more about gRPCs here](https://grpc.io/docs/what-is-grpc/introduction/).
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
  version-hash     Display CLI version hash
  info             Display high-level information about the Gateway
  balance          Check gateway balance
  address          Generate a new peg-in address, funds sent to it can later be claimed
  deposit          Deposit funds into a gateway federation
  withdraw         Claim funds from a gateway federation
  connect-fed      Connect federation with the gateway
  help             Print this message or the help of the given subcommand(s)

Options:
  -a, --address <ADDRESS>          The address of the gateway webserver [default: http://127.0.0.1:8175]
      --rpcpassword <RPCPASSWORD>  WARNING: Passing in a password from the command line may be less secure!
  -h, --help                       Print help information
  -V, --version                    Print version information
```

### mintgate

A simple and delightful admin dashboard for everyday access and control of your Fedimint gateway. Currently [under development here](https://github.com/GETLN/mintgate)

---

## Developing the Gateway

As described in [Running Fedimint for dev testing](./dev-running.md#using-the-gateway), running `./scripts/tmuxinator.sh` starts a local development Federation instance with a running Gateway instance attached. You can interact with this Gateway via `gateway-cli`.

### Developing gateway-lnrpc-extension

- See and contribute to [gateway-cln-extension](../gateway/ln-gateway/src/bin/cln_extension.rs)
- Help add support to other node implementations by building [gateway-lnrpc-extensions](#gateway-lnrpc-extension) for them. You can parent your brand-new extension in this directory, or in your own repository and we will link to it in this open documentation
- Contributions are highly welcome!

## Deploying a Gateway in Production

### Deploy a gateway-lnrpc-extension

- [gateway-cln-extension](../gateway/ln-gateway/src/bin/cln_extension.rs): **TODO:** Add docs here
- other _gateway-lnrpc-extension_:  **TODO:** Add docs here

### Configure and deploy gatewayd

- **TODO:** Add docs here

### Provisioning liquidity for a Lightning Gateway

- **TODO:** Add docs here

### Register and Serve Federations

- **TODO:** Add docs here
