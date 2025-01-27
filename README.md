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

## Using Fedimint

To use Fedimint you only need a client application, that will allow interacting with
Fedimint federations.

You can pick one of Fedimint-supporting applications:

* [Fedi](https://www.fedi.xyz/) - for MacOS, Android and Web browsers
* [Harbor Wallet](https://harbor.cash/) - desktop wallet
* [Mutiny Wallet](https://www.mutinywallet.com/) - web wallet
* `fedimint-cli` - Fedimint's built in CLI wallet for developers and automation

## Running your own Fedimint federation

If you are interested in setting up a Fedimint federation, refer to [Running your own Fedimint federation](./docs/deploying.md).

## Developing Fedimint

We are actively looking for developers to help build Fedimint and associated open-source Bitcoin projects. Fedimint
touches many different areas of Bitcoin development, so there is something for everyone. The best places to get started
are:

- [Fedimint Hacking Guide](./HACKING.md#) for information about working on the code.
- [Fedimint Contributing Guidelines](CONTRIBUTING.md#) for information for contributors.
- [Fedimint Developer Discord Server](https://discord.gg/cEVEmqCgWG): the best place to get help and ask questions.
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
