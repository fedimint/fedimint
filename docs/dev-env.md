# Set up local dev environment

## Clone repository

Clone this repository locally, with `git clone <repo-url>`, then `cd <repo-dir>`,

## MacOS

If you're installing on macOS, refer to the [macOS Guide](./macos.md) instead of this file.

## Set up Nix

Fedimint uses [Nix](https://nixos.org/explore.html) for building, CI, and managing dev environment.
Note: only `Nix` (the language & package manager) and not the NixOS (the Linux distribution) is needed.
Nix can be installed on any Linux distribution and macOS.

While it is technically possible to not use Nix, it is highly recommended as
it ensures consistent and reproducible environment for all developers.

### Install Nix

If you don't have it set up already,
follow the instructions at: https://nixos.org/download.html

The end result is having a working `nix` command in your shell.

Example:

```
> nix --version
nix (Nix) 2.9.1
```

The exact version might be different.

### Enable nix flakes

Edit either `~/.config/nix/nix.conf` or `/etc/nix/nix.conf` and add:

```
experimental-features = nix-command flakes
```

If the Nix installation is in multi-user mode, don’t forget to restart the nix-daemon.

## Use Nix Shell

If your Nix is set up properly `nix develop` started inside the project dir should just work
(though it might take a while to download all the necessary files and build all the internal
tooling). In the meantime you can read other documentation.

**Using `nix develop` is strongly recommended**. It takes care of setting up
all the required developer automation, checks and ensures that all the developers and CI are 
in sync: working with same set of tools (exact versions).

You can still use your favorite IDE, Unix shell, and other personal utilities, but they MUST NOT
be expected to be a requirements for other developers. In other words: if it's not automated
and set up in `nix develop` shell, it doesn't exist from team's perspective.

To use a different shell for `nix develop`, try `nix develop -c zsh`. You can alias it if
don't want to remember about it. That's the recommended way to use a different shell
for `nix develop`.


## Setting up `direnv` or `lorri`

One of the biggest QoL improvements you can do when working with flake-enabled project
is setting up one of:

* https://github.com/nix-community/nix-direnv
* https://github.com/nix-community/lorri

The projects will set up your system's shell so that when you `cd` inside a given
project they will automatically set up the environment for you, without starting any
new shells. This way you can preserve your shell, and your settings while using
`nix develop`-like shell automatically.
