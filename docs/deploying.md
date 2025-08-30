# Setting up Federations

The preferred way to run Fedimint is with multiple **guardian servers** working together in a federation. Fedimint is
built to be **Byzantine Fault Tolerant**, meaning it can continue functioning even if some guardians act maliciously.
Specifically, a federation with `3m + 1` guardians can tolerate up to m malicious guardians. For example:
	•	A federation with 4 guardians can handle 1 malicious guardian.
	•	A federation with 7 guardians can handle 2 malicious guardians.

You can also run Fedimint in **solo mode** with just one guardian. While this is useful for testing or development, it
is not recommended for real-world use since it lacks the resilience of a federation with multiple guardians.

To support **Lightning payments**, Fedimint requires a **Lightning Gateway**. This is a participant in the federation
that swaps ecash for sending and receiving Lightning payments. Note that the Lightning Gateway is not a guardian—it's an
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

### Setting Up a Federation
You can create a Fedimint in two ways:
- Single Guardian Federation — A single guardian operating their own mint.
- Group Federation — Multiple guardians running the mint together (minimum of 4 guardians).

### Step By Step Ceremony
1. Install & Launch `fedimintd`
	Each participating guardian runs their own instance of fedimintd.
	See below [self-hosted solutions](#self-hosted-solutions) or [hosted solutions](#hosted-solutions) for installation options.
2. Set a Password
	When starting fedimintd for the first time, each guardian must create a secure password.
3. Generate Setup Code
	After entering the password, a unique setup code is generated for each guardian.
4. Exchange Setup Codes
	All guardians must share their setup codes with each other (every guardian needs every other guardian’s code).
5. Distributed Key Generation (DKG)
	Once all setup codes are entered, the DKG process begins. This is where the federation’s cryptographic keys are jointly created.
	This step may take some time while all guardians connect.
6. Federation Complete!
	Once DKG finishes, your federation is live. Your guardian dashboard will be available for monitoring. You now have a functioning Fedimint!

In addition, a practical federation requires a Lightning Gateway
to join the federation, and someone needs to set it up and
run, though one gateway can join and server multiple
federations. It is currently recommend to use an existing Lightning Gateway, but you can run your own.

See [here](../docs/gateway.md) for more information about the Lightning Gateway.

## Self-hosted solutions

Due to diverse nature of server-side software, it is impossible to come up with a single
guide that would cover all scenarios. We are trying to create and maintain guides
and solutions for variety of cases.


* [`./docker` directory](../docker/README.md) - for information regarding Docker support.
* [Fedimint NixOS Deployment Repo](https://github.com/fedimint/nixos-deployment) - an example template for setting up Fedimint using NixOS server.


## Hosted solutions

* [Clovyr hosted Fedimint](https://clovyr.app/tag/fedimint)
* [Nodana hosted Fedimint](https://nodana.io/services/fedimintd)

## Help and support

For help please try [Fedimint Github Discussions](https://github.com/fedimint/fedimint/discussions)
or `#mint-ops` channel on [Fedimint's Discord server](https://chat.fedimint.org/).
