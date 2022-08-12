# Background

The Fedimint developer environment is based on [Nix](https://nixos.org/), which supports MacOS but works much more smoothly on Linux.

If you have trouble setting up a Nix environment directly on Mac, try one of these methods and report back how it worked for you.

# Multipass

[Multipass](https://multipass.run/) is a CLI from Canonical for managing Ubuntu VMs.

### Setup

 - `%` indicates a command ran in your macOS enviroment
 - `$` indicates a command ran inside the Ubuntu VM
 - `#` indicates a comment
 
```shell
% brew install --cask multipass
# pick appropriate resource allocation for your device
% multipass launch 22.04 --name fedidev --cpus 8 --mem 6G --disk 12G 
% multipass shell fedidev
$ sudo apt-get install build-essential
$ sh <(curl -L https://nixos.org/nix/install) --daemon
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ git clone https://github.com/fedimint/fedimint
$ cd fedimint
$ ./scripts/tmuxinator.sh
# you should now have a fully setup federation with all the backing bitcoin infrastrucure running locally
```

### Editor Support

 - [VScode to ssh remotely](https://dev.to/josuebustos/vs-code-remote-ssh-multipass-dn8)
 - IntelliJ also has this feature

# Devcontainers

TODO ...