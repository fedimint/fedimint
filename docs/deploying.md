# Setting up Federations

The preferred way to run Fedimint is with multiple **guardian servers** working together in a federation. Fedimint is
built to be **Byzantine Fault Tolerant**, meaning it can continue functioning even if some guardians act maliciously.
Specifically, a federation with `3m + 1` guardians can tolerate up to m malicious guardians. For example:
	•	A federation with 4 guardians can handle 1 malicious guardian.
	•	A federation with 7 guardians can handle 2 malicious guardians.

You can also run Fedimint in **solo mode** with just one guardian. While this is useful for testing or development, it
is not recommended for real-world use since it lacks the resilience of a federation with multiple guardians.

To support **Lightning payments**, Fedimint requires a **Lightning Gateway**. This is a participant in the federation
that swaps ecash for sending and receiving Lightning payments. Note that the Lightning Gateway is not a guardian—it’s an
untrusted economic actor that interacts with the federation.

## Target audience

Using an existing Fedimint federation as an user is easy and comes
down to downloading a client application on a device like a phone.

Setting up and maintaining Federation is more challenging as it
requires better understanding of its architecture and handling of its
server side components.

In near future we expect many hosted Fedimint solutions, which should
make setting up federations relatively easy.

Self-hosting your own federation is preferable. It is very similar
to self-hosting any other software and requires some technical
understanding in this area.

## Overview

What federation really is are 4 or more Guardians independently running `fedimintd` node software.

A `fedimintd` setup requires:

* setting DNS domain
* prunned `bitcoind` node
* TLS termination software like `caddy` or `nginx`


In addition, a practical federation requires a Lightning Gateway
to join the federation, and someone needs to set it up and
run, though one gateway can join and server multiple
federations.

A `ln-gateway` setup requires:

* an unprunned `bitcoind` node
* possibly setting up lightning node

## Self-hosted solutions

Due to diverse nature of server-side software, it is impossible to come up with a single
guide that would cover all scenarios. We are trying to create and maintain guides
and solutions for variety of cases.


* [`./docker` directory](../docker/README.md) - for information regarding Docker support.
* [Fedimint NixOS Deployment Repo](https://github.com/fedimint/nixos-deployment) - an example template for setting up Fedimint using NixOS server.
* [Fedimint Mutinynet Setup Guide](./deploying/docker-mutiny.md) - a detailed guide setting up both Fedimint and Lightning Gateway using `docker`.


## Hosted solutions

* [Clovyr hosted Fedimint](https://clovyr.app/tag/fedimint)
* [Nodana hosted Fedimint](https://nodana.io/services/fedimintd)

## Help and support

For help please try [Fedimint Github Discussions](https://github.com/fedimint/fedimint/discussions)
or `#mint-ops` channel on [Fedimint's Discord server](https://chat.fedimint.org/).
