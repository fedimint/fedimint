# Set up local dev environment

## Script version

This instruction is available in a script version. If you prefer it, you can run:

```
git clone -o upstream https://github.com/fedimint/fedimint && cd fedimint && ./scripts/bootstrap.sh
```

and follow the instructions instead of reading this document.

## Clone repository

Clone this repository locally, with `git clone <repo-url>`, then `cd <repo-dir>`,

## MacOS

If you encounter problems with Nix on MacOS, refer to the [macOS Guide](./macos.md).

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

#### _Preclude nix shell + tmux problems_
Some of the scripts and examples in this repository make use of the `tmux` terminal multiplexer. 
However, by default a tmux instance launches a _login shell_, which can lead to unintended problems 
on certain operating systems (e.g. Debian)[^1]. Especially, when `tmux` is launched within a _nix shell_,
as needed for [Running Fedimint for dev testing](./dev-running.md).

You can preclude these problems by forcing `tmux` to always use non-login shells. Create (or edit) a `.tmux.conf`
in your home directory with the following line:

```
set -g default-command "${SHELL}"
```

## Setting up `direnv` or `lorri`

One of the biggest QoL improvements you can do when working with flake-enabled project
is setting up one of:

* https://github.com/nix-community/nix-direnv
* https://github.com/nix-community/lorri

The projects will set up your system's shell so that when you `cd` inside a given
project they will automatically set up the environment for you, without starting any
new shells. This way you can preserve your shell, and your settings while using
`nix develop`-like shell automatically.

[^1]: [issues/506](https://github.com/fedimint/fedimint/issues/506): scripts/tmuxinator.sh prerequisites and issues

## Cross-compilation

Dev environment comes with support for cross-compilation. However since most developers
are not going use it while it requires heavy dependencies like Android NDK, it is only
available in a separate Nix dev shell. To start it, use:

```
nix develop .#cross
```

Inside the shell cross-compilation commands like:

```
cargo build --target wasm32-unknown-unknown
```

should work as expected.

## Containers

The `flake.nix` exposes OCI container builds of Fedimint (search for "container"). To use them
try:

```
$ nix build .#container.fedimintd && docker load < ./result
Loaded image: fedimintd:iqviraxy2cz7apg7qamcp2mbsy7x7w8r
```

Change `.#container.fedimintd` to build a different container.
The `Loaded image:` lists the image name that `docker` will use.

```
$ docker images | grep iqviraxy2cz7apg7qamcp2mbsy7x7w8r
fedimintd     iqviraxy2cz7apg7qamcp2mbsy7x7w8r      fad75f704001   52 years ago    68.6MB
```

You can start the binary(-ies) inside with the usual:

```
$ docker run -it fedimintd:iqviraxy2cz7apg7qamcp2mbsy7x7w8r fedimintd --help
Usage: fedimintd <CFG_PATH> <DB_PATH>

Arguments:
  <CFG_PATH>
  <DB_PATH>

Options:
  -h, --help  Print help information
```

Most commands will require access to some host mounted volumes and port bindings.
For your convenience, here is an example:


```
$ docker run -it -v $PWD/demo:/var/fedimint fedimintd:iqviraxy2cz7apg7qamcp2mbsy7x7w8r configgen generate --out-dir /var/fedimint --num-nodes 3 --denominations 1,2,5
Generating keys such that up to 0 peers may fail/be evil
$ ls demo
client.json  server-0.json  server-1.json  server-2.json
```

`-v` will mount local directory `./demo` as `/var/fedimint` inside the container, so the `--out-dir /var/fedimint` writes the files to the host file-system

```
$ docker run -it -v $PWD/demo:/var/fedimint -p 17240:17240 fedimintd:iqviraxy2cz7apg7qamcp2mbsy7x7w8r fedimintd  /var/fedimint/server-0.json /var/fedimint/server-0.db
... output logs ...
```

Again, `-v` is used to mount directory with the generated configs, while `-p` is used to bind the host's port 17240 as the container's port 17240.
