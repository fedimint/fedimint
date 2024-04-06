# Fedimint Technical Reference Documentation

<!-- this page is used a landing page for https://docs.fedimint.org/ -->
<!-- lots of links in this document are relative to the generated document, so disabling linkcheck altogether: -->
<!-- markdown-link-check-disable -->

## Target audience

This documentation is automatically generated from the Fedimint source code,
and it's meant for developers, builders and people who want to understand
the Fedimint project on an implementation level.

If you are looking for higher level documentation and help, please check:

* [Fedimint website](https://fedimint.org/)
* [Fedimint github](https://github.com/fedimint/fedimint)
* [Fedimint chat](https://chat.fedimint.org/)

## State

This is a recently added document and subject of continuous change. Please report problems and submit improvements.

# Overview

Fedimint is implemented in [Rust](https://www.rust-lang.org/) and consists of multiple Rust crates.
On a high-level Fedimint architecture consist of:

* Server side: [`fedimintd`](./fedimintd/index.html) daemon typically running on Linux servers, serving a role of a a "peer" in a Federation by communicating with other "peers" to form a consensus.
* Client side: [`fedimint-client`](./fedimint_client/index.html) library, that handles client side state handling and
communication with Fedimint peers. This library can be used to build Fedimint client applications that can run on
desktop computers, mobile devices and in web browsers (WASM).

More high level documentation is available as a part of [`fedimint-docs`](./fedimint_docs/indiex.html) crate.

# Modules

Fedimint architecture is extensible using a modular design. Fedimint modules can build on top of Fedimint consensus to implement additional functionality and applications.

In fact core functions of Fedimint are implemented as modules:

* [fedimint-mint-server](./fedimint_mint_server/index.html) and [fedimint-mint-client](./fedimint_mint_client/index.html) implement ecash.
* [fedimint-wallet-server](./fedimint_wallet_server/index.html) and [fedimint-wallet-client](./fedimint_wallet_client/index.html) implement on-chain deposits and withdrawals.
* [fedimint-ln-server](./fedimint_ln_server/index.html) and [fedimint-ln-client](./fedimint_ln_client/index.html) implement lightning integration.

Some additional built-in modules are also available:

* [fedimint-meta-server](./fedimint_meta_server/index.html) and [fedimint-meta-client](./fedimint_meta_client/index.html) implement guardian managing additional ("meta") information about the Federation.
* [fedimint-empty-server](./fedimint_empty_server/index.html) and [fedimint-empty-client](./fedimint_empty_client/index.html) are a reference "empty" module that can be used as a starting point for new modules.
* [fedimint-dummy-server](./fedimint_dummy_server/index.html) and [fedimint-dummy-client](./fedimint_dummy_client/index.html) are a test-only modules, possibly useful as a simple example.

Developers and builders are encouraged to create their own modules. Check ["Fedimint Modules" Discussions](https://github.com/fedimint/fedimint/discussions/categories/fedimint-modules/index.html) for ideas and help.

# Notable crates

You might consider viewing the following top-level crates:

* [fedimint-core](./fedimint_core/index.html) is a core common code shared between client and server.
* [fedimint-cli](./fedimint_cli/index.html) is a command line client.
* [fedimint-client](./fedimint_client/index.html) is a client library.
* [fedimint-server](./fedimint_server/index.html) is a core server side logic.
* [gatewayd](./gatewayd/index.html) is a LN Gateway implementation.
* [gateway_cli](./ln_gateway/index.html) is a command line client for LN Gateway.
* [fedimint_dbtool](./fedimint_dbtool/index.html) implements a helpful database helper tool.
* [recoverytool](./recoverytool/index.html) implements an on chain multisig recovery tool for defunct/test Federations.
