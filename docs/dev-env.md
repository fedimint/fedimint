# Set up local dev environment

## Script version

This instruction is available in a script version. If you prefer it, you can run:

```
git clone -o upstream https://github.com/fedimint/fedimint && cd fedimint && ./scripts/dev/bootstrap.sh
```

and follow the instructions instead of reading this document.

## Clone repository

Clone the fedimint git repository locally and cd into it:

```
git clone git@github.com:fedimint/fedimint.git
cd fedimint
```

## Set up Nix

Fedimint uses [Nix](https://nixos.org/explore.html) for building, CI, and managing dev environment.
Note: only `Nix` (the language & package manager) and not the NixOS (the Linux distribution) is needed.
Nix can be installed on any Linux distribution and macOS.

While it is technically possible to not use Nix, it is highly recommended as
it ensures consistent and reproducible environment for all developers.

### Install Nix

You have 2 options to install nix:
* [The official installer](https://nixos.org/download.html)
* The [Determinate Nix Installer](https://zero-to-nix.com/start/install) which is maintained by a 3rd party, but is a little more user-friendly.

If one doesn't work for you, consider trying the other. The end result is having a working `nix` command in your shell.

Example:

```
> nix --version
nix (Nix) 2.9.1
```

The exact version might be different.

### Enable nix flakes

If you installed Nix using the "determinate installer" you can skip this step. If you used the "official installer", edit either `~/.config/nix/nix.conf` or `/etc/nix/nix.conf` and add:

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
and set up in `nix develop` shell, it doesn't exist from the team's perspective.

To use a different shell for `nix develop`, try `nix develop -c zsh`. You can alias it if
don't want to remember about it. That's the recommended way to use a different shell
for `nix develop`.

## Cachix binary cache

Fedimint uses a [Cachix](https://www.cachix.org/) binary cache to cache builds.
To benefit from this cache and avoid building everything from scratch, you must
ensure that your user is a [trusted user](https://nixos.org/manual/nix/stable/command-ref/conf-file.html#conf-trusted-users).
You can do this by modifying `/etc/nix/nix.conf`, adding the following line.

```
trusted-users = the_name_of_your_user
```

Alternatively, if you do not want to add your user to the list of trusted users, you can
run the following command, which will add <https://fedimint.cachix.org> and its public key
to your nix configuration.

```
nix develop .#bootstrap -c cachix use fedimint
```

## Setting up `direnv` or `lorri`

One of the biggest QoL improvements you can do when working with flake-enabled projects
is setting up one of:

* https://github.com/nix-community/nix-direnv
* https://github.com/nix-community/lorri

The projects will set up your system's shell so that when you `cd` inside a given
project they will automatically set up the environment for you, without starting any
new shells. This way you can preserve your shell, and your settings while using
`nix develop`-like shell automatically.

## Cross-compilation

Dev environment comes with support for cross-compilation. However since most developers
are not going use it while it requires heavy dependencies like Android NDK, it is only
available in a separate Nix dev shell. To start it, use:

```
nix develop .#cross
```

Inside the shell cross-compilation commands like:

```
cargo build --target wasm32-unknown-unknown --package fedimint-client
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
Usage: fedimintd [OPTIONS] <DATA_DIR> [PASSWORD]

Arguments:
  <DATA_DIR>  Path to folder containing federation config files
  [PASSWORD]  Password to encrypt sensitive config files [env: FM_PASSWORD=]

Options:
  -h, --help                   Print help information
```

Most commands will require access to some host mounted volumes and port bindings.
For your convenience, here is an example:

```
$ docker run -it -v $PWD/demo:/var/fedimint -p 17240:17240 fedimintd:iqviraxy2cz7apg7qamcp2mbsy7x7w8r configgen <command>
```

`-v` will mount local directory `./demo` as `/var/fedimint` inside the container, so commands working on `/var/fedimint`
write the files to the host file-system (e.g. config generation). `-p` is used to bind the host's port 17240 as the
container's port 17240.

Note that you can also start a "fake" 1-of-1 "federation" that will allow you to test most aspects of Fedimint without
having to run e.g. 4 instances.
