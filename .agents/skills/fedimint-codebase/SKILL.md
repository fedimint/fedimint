---
name: fedimint-codebase
description: >-
  Use before navigating the Fedimint codebase, deciding where a change belongs,
  or working across its components, modules, consensus, or client state
  machines.
---

# Fedimint Codebase

Fedimint is a modular framework for building federated financial applications.
It provides a trust-minimized, censorship-resistant, and private alternative to
centralized applications. The core implementation focuses on a federated
Chaumian e-cash mint that is natively compatible with Bitcoin and the Lightning
Network.

## Core components

- **fedimint-core** — Core framework, types, and utilities shared between client
  and server.
- **fedimint-server** — Federation consensus logic using AlephBFT.
- **fedimint-client** — Client library for interacting with federations.
- **modules/** — Pluggable modules such as mint, wallet, lightning, and meta.
- **gateway/** — Lightning gateway for payment routing.

## Module structure

Each module follows a three-crate pattern:

```text
fedimint-<module>-common/     # Shared types and config
fedimint-<module>-client/     # Client-side functionality
fedimint-<module>-server/     # Server-side consensus logic
```

Key modules include:

- **Mint** (`fedimint-mint-*`) — Chaumian e-cash implementation.
- **Wallet** (`fedimint-wallet-*`) — Bitcoin on-chain functionality.
- **Lightning** (`fedimint-ln-*`, `fedimint-lnv2-*`) — Lightning Network
  integration.
- **Meta** (`fedimint-meta-*`) — Federation metadata management.

## Entry points

- `fedimintd/src/bin/main.rs` — Federation node daemon.
- `fedimint-cli/src/main.rs` — Command-line client interface.
- `gateway/fedimint-gateway-server/src/bin/main.rs` — Lightning gateway.

## Architecture and design patterns

Consensus uses:

- Byzantine fault-tolerant consensus with AlephBFT.
- Epoch-based transaction processing.
- Module-specific consensus contributions.
- Async state machines for client operations.

Important design patterns include:

- **Extensible module system** — Modules implement `ServerModule` and
  `ClientModule`.
- **Type-safe encoding** — Custom `Encodable` and `Decodable` traits use module
  registries.
- **Operation-based client API** — Long-running operations use `OperationId`
  tracking.
- **Database abstraction** — A key-value store uses module-specific
  namespacing.

## Testing and organization

The testing strategy includes:

- Integration tests using the `devimint` development environment.
- Module-specific test suites in `fedimint-*-tests` crates.
- Database migration testing with snapshot validation.
- WASM compatibility verification.
- Real-service testing against bitcoind and Lightning nodes.

The workspace has more than 78 member crates. It uses Nix for reproducible
development, `just` for common automation, `mprocs` for multi-process
development, and an extensive compatibility-testing CI pipeline.
