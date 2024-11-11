<h1 align="center">
  <a href="https://fedimint.org">
    Fedimint
  </a>
</h1>

<p align="center">
    <img src="docs/banner.png">
</p>

<p align="center">
  <a href="https://github.com/fedimint/fedimint/actions/workflows/ci-nix.yml">
      <img src="https://github.com/fedimint/fedimint/actions/workflows/ci-nix.yml/badge.svg" alt="GitHub Actions CI Build Status">
  </a>
  <a href="https://chat.fedimint.org"><img alt="Developer Discord Chat" src="https://img.shields.io/discord/990354215060795454?label=dev%20chat"></a>
  <a href="https://github.com/fedimint/fedimint/discussions">
    <img src="https://img.shields.io/badge/community-discussion-blue" alt="GitHub Discussion">
  </a>
  <a href="https://docs.fedimint.org">
    <img src="https://img.shields.io/static/v1?label=Docs&message=master&color=007ec6&logo=GitBook&logoColor=ffffff" alt="docs built from master">
  </a>
  <a href="https://app.radicle.xyz/nodes/radicle.fedimint.org/rad:z2eeB9LF8fDNJQaEcvAWxQmU7h2PG">
    <img src="https://img.shields.io/badge/Radicle-explore-blue" alt="View on Radicle">
  </a>
  <img alt="Lines of code" src="https://tokei.rs/b1/github/fedimint/fedimint">
</p>

[Fedimint](https://fedimint.org) is a module based system for building federated applications. It is designed to be a
trust-minimized, censorship-resistant, and private alternative to centralized applications.

> **Fedimint is beta software released under
an [MIT License](https://github.com/fedimint/fedimint/blob/master/LICENSE). This means that the software here is
provided "as is", without warranty of any kind. We are a small development team with limited resources. If you
experience a loss of funds due to a bug in this software, we may not have the means to help you recover the funds. We
recommend you run Fedimint on testnets like mutinynet, or on mainnet with small amounts of money. You can find our
latest release [here](https://github.com/fedimint/fedimint/releases/latest).**

Fedimint ships with 3 default
modules - [Bitcoin](https://github.com/bitcoin/bitcoin), [Lightning](https://github.com/lightning/bolts),
and [Chaumian Ecash](https://en.wikipedia.org/wiki/Ecash) - for out-of-the-box best practices for private and
trust-minimized payments. [You can write custom modules](https://github.com/fedimint/fedimint-custom-modules-example)
that define further consensus items and transaction types leveraging the payments modules to build your own federated
applications.

The Fedimint Developer Discord is the best place to get help and ask
questions. [Join the Discord](https://discord.gg/cEVEmqCgWG) and say hi! We are extremely active and work to onboard
developers of all skill levels to Fedimint and associated open-source Bitcoin projects. Fedimint touches many different
areas of Bitcoin development, so there is something for everyone. See below for more information on how to get involved.

## Running your own Fedimint

It's easy to set up and run your own federations. Fedimint is designed to
be [Byzantine Fault Tolerant](https://en.wikipedia.org/wiki/Byzantine_fault) so is resilient to `m` malicious nodes in a
federation of `3m + 1` nodes. If you run a federation of 4 guardians you are resilient to 1 malicious guardian, if you
run a federation of 7 guardians you are resilient to 2 guardians, etc.

Fedimint can also be run in "solo mode" with a single guardian. This is useful for testing and development, but is not
recommended for production use.

To do lightning payments, Fedimint requires
a [Lightning Gateway](https://github.com/fedimint/fedimint/blob/master/docs/gateway.md): a user of the federation that
is willing to swap ecash in exchange for sending/receiving lightning payments. The Lightning Gateway is not a guardian
and acts as an untrusted economic actor serving the federation.

### Running Fedimint on Mutinynet

See the [Fedimint Mutinynet Setup Guide](./docs/setup-docs.md). You can modify the configuration options to deploy it
with.

## For Developers

We are actively looking for developers to help build Fedimint and associated open-source Bitcoin projects. Fedimint
touches many different areas of Bitcoin development, so there is something for everyone. The best places to get started
are:

- [The Fedimint Developer Discord](https://discord.gg/cEVEmqCgWG): the best place to get help and ask questions.
- [Fedimint Technical Reference Documentation](https://docs.fedimint.org)
- [Fedimint Contributor Calendar](https://calendar.google.com/calendar/u/0/embed?src=fedimintcalendar@gmail.com): This
  calendar contains all the developer calls and events.
- [Fedimint Developer Calls](https://meet.jit.si/fedimintdevcall): We have developer calls every Monday at 4PM UTC to
  review PRs and discuss current development priorities. As a new developer, this is a great place to find good first
  issues and mentorship from the core team on how to get started contributing to Fedimint.
- [PR Review Club](https://meet.jit.si/fedimintdevcall): We have PR review calls every Tuesday at 4PM UTC.
- [Weekly Deep Dive](https://meet.jit.si/fedimintdevcall): We have a deep dive every Thursday at 4PM UTC to discuss
  technical topics relating to Fedimint in depth: cryptography, Rust programming, consensus, networking, etc. This is a
  great place to learn about the internals of Fedimint and Bitcoin. We normally plan these calls based off requests from
  contributors on aspects of Fedimint they want to learn more about, so please reach out if you have a topic you want to
  learn more about.

For contribution guidelines, Areas of contributions and how to get involved, please refer to
the [Contributing Guidelines](CONTRIBUTING.md).

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

# Maintainers

| Area              | Lead-Maintainer    | Co-Maintainers               | Status                                |
|-------------------|--------------------|------------------------------|---------------------------------------|
| Project Lead      | @elsirion          | @dpc @joschisan              | X                                     | 
| Core Server       | @joschisan         | X                            | mostly well factored, no known issues | 
| Core Consensus    | @joschisan         | @bradleystachurski           | polished and documented               | 
| Lightning Module  | @joschisan         | @m1sterc001guy               | active development, known issues      |
| Mint Module       | @joschisan         | X                            | active development, known issues      |
| Wallet Module     | @bradleystachurski | @dpc @joschisan              | active development, critical issues   |
| Core Client       | @dpc               | X                            | X                                     |
| Lightning Gateway | @m1sterc001guy     | @joschisan                   | X                                     |
| Database          | @m1sterc001guy     | X                            | X                                     |
| Networking        | X                  | X                            | X                                     |
| CI / Nix          | @dpc               | @maan2003 @bradleystachurski | X                                     |
| Testing           | @bradleystachurski | X                            | X                                     |
| Devimint          | @maan2003          | X                            | X                                     |
| Config Generation | X                  | X                            | X                                     |
