# Fedimint Hacking Guide

### Fedimint Repos and Projects to Contribute To

- [Fedimint](https://github.com/fedimint/fedimint/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22): The
  core Fedimint repository. This is where the core consensus and networking code lives. Fedimint is an advanced Rust
  project and is a great place to learn Rust, cryptography, networking, consensus, and bitcoin development. We have a
  lot of good first issues, are happy to mentor new developers, and are always looking for experienced Rust developers
  to help with the core codebase.
- [UI](https://github.com/fedimint/ui): The default Fedimint Guardian and Lightning Gateway UIs. These are Typescript
  and React projects. Contributing to this repo helps with UI/UX design and development to make Fedimint more user
  friendly.
- [Lightning Gateway](https://github.com/fedimint/fedimint/issues?q=is%3Aissue+is%3Aopen+label%3Alightning): Fedimint's
  Lightning Gateway is implemented as an HTLC interceptor and currently works with CLN, LND, and LDK's sample-node
  implementations. We are always looking for lightning developers to help with the Lightning Gateway, especially around
  improving payment reliability and to add support for more lightning implementations.
- [Custom Modules](https://github.com/fedimint/fedimint-custom-modules-example): Fedimint ships with 3 default modules:
  Bitcoin, Lightning, and Chaumian Ecash. You can write custom modules that define further consensus items and
  transaction types leveraging the payments modules to build your own federated applications. We are always looking for
  developers to help build custom modules and to help improve the module system.
- [Fedimint Web SDK](https://github.com/fedimint/fedimint-web-sdk): The Fedimint Web SDK is a Typescript library for
  building Fedimint applications. We are looking for developers to help improve the SDK and add support for more features.

## Spinning up the Fedimint Developer Environment

Fedimint is a Rust project and uses the [Nix package manager](https://nixos.org/) to manage dependencies and build the
project.

### Local Development

We have a detailed tutorial on how to use the cli to send/receive ecash, lightning payments, and perform other developer
operations in the [Fedimint Developer Tutorial](https://github.com/fedimint/fedimint/blob/master/docs/tutorial.md).

Fedimint's developer environment and rust build pipeline is managed
through [Nix Flakebox](https://github.com/rustshop/flakebox). To get started, install Nix.

```bash
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```

Then fork and clone the Fedimint repo.

```bash
git clone https://github.com/your-username/fedimint.git
```

Then enter the nix developer environment.

```bash
nix develop
```

and use this command to start a local regtest network with 4 guardians, a bitcoin node, and a lightning gateway.

```bash
just mprocs
```

You can then interact with the guardians and lightning gateway using the cli. For more details on how to use the cli,
see the [Fedimint Developer Tutorial](https://github.com/fedimint/fedimint/blob/master/docs/tutorial.md).

If you want to run with UIs, see the [UI](https://github.com/fedimint/ui) repo for developer environment instructions.
