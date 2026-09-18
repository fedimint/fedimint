# ARCH-fedimint: Fedimint architecture

Fedimint is a modular framework for federated applications. Its primary deployment is a federation of guardian processes that jointly execute deterministic consensus and expose APIs to clients; the default modules provide Chaumian e-cash, Bitcoin on-chain custody, and Lightning payments.

## System boundaries

- `fedimintd` assembles server modules and runs one guardian. Before a federation exists, guardians exchange setup information and jointly generate configuration and cryptographic key material. After setup, guardian-to-guardian networking orders core and module consensus items, and every honest guardian applies the same ordered outcomes to its local database.
- `fedimint-core`, `fedimint-server-core`, and `fedimint-client-module` define shared encodings, configuration, module interfaces, and common infrastructure. `fedimint-server` owns setup, networking integration, consensus execution, and server configuration; `fedimint-client` owns persistent client operations and module state machines.
- Modules normally separate common wire and configuration types from client and server implementations. The daemon and clients select implementations through module registries, while a federation's generated consensus configuration fixes the enabled module instances.
- Clients use federation configuration to query multiple guardians, submit transactions, and drive durable module operations. Gateways are federation clients that also connect to external Lightning nodes and mediate Lightning payments; they are not guardians and do not participate in federation consensus.

## Configuration boundary

Guardian setup converts operator-selected parameters and exchanged peer setup codes into private, local, and consensus server configuration. The consensus portion must be identical across guardians and determines the federation and module configuration visible to clients. [SPEC-dkg-version-compatibility](SPEC-dkg-version-compatibility.md) constrains which daemon builds may participate in one setup ceremony and how that decision is reflected in the generated consensus configuration.

See the [project overview](../README.md), [deployment guide](../docs/deploying.md), [modular architecture](../docs/modular-architecture.md), and [networking notes](../docs/networking.md) for operational and implementation detail.
