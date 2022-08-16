# Background

The Fedimint developer environment is based on [Nix](https://nixos.org/), which supports MacOS but works much more smoothly on Linux.

If you have trouble setting up a Nix environment directly on Mac, try one of these methods and report back how it worked for you.

# Multipass

[Multipass](https://multipass.run/) is a [CLI](https://multipass.run/docs/multipass-cli-commands) from Canonical for managing Ubuntu VMs.

### Setup

 - `%` indicates a command ran in your macOS enviroment
 - `$` indicates a command ran inside the Ubuntu VM
 - `#` indicates a comment
 
```shell
% brew install --cask multipass
# pick appropriate resource allocation for your device, disk should be >= 20G
% multipass launch 22.04 --name fedidev --cpus 8 --mem 6G --disk 20G 
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

#### [VScode](https://dev.to/josuebustos/vs-code-remote-ssh-multipass-dn8): remote SSH setup

 ```shell
% multipass info fedidev  # write down the IPv4 address of VM
% nano ~/.ssh/config
# update mac ssh config with vm info:
#  Host [alias for VM]
#    HostName [IPv4 address of VM]
#    User ubuntu

% pbcopy < ~/.ssh/id_rsa.pub  # get your mac pubkey, may be in different file
$ nano ~/.ssh/authorized_keys  # paste mac pubkey in this file on vm

# install VSCode extension Remote - SSH 
# follow instructions in "Connect to a VM Instance in VS Code" section of https://dev.to/josuebustos/vs-code-remote-ssh-multipass-dn8
 ```
 
 #### IntelliJ

# Devcontainers

TODO ...