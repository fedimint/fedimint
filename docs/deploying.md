# Setting up Fedimint federation

This guide is meant for users interested in being Fedimint guardians
and setting up own federation.

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

What federation really is are 4 or more Guardians independently running `fedimintd` server software.

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

## Guides

Due to diverse nature of server-side software, it is impossible to come up with a single
guide that would cover all scenarios. We are trying to create and maintain guides
for variety of cases.

For help please try [Fedimint Github Discussions](https://github.com/fedimint/fedimint/discussions)
or #mint-ops channel on [Fedimint dev chat](https://chat.fedimint.org/).

Please see following guides:

* [Fedimint Mutinynet Setup Guide](./deploying/docker-mutiny.md) - a detailed guide setting up both Fedimint and Lightning Gateway using `docker`
* [Fedimint NixOS Deployment Repo](https://github.com/fedimint/nixos-deployment) - an example template for setting up Fedimint using NixOS server.
