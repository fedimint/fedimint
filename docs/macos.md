# Background

The Fedimint developer environment is based on [Nix](https://nixos.org/), which supports MacOS but works much more smoothly on Linux.

If you have trouble setting up a Nix environment directly on Mac, try one of these methods and report back how it worked for you.

# Multipass

[Multipass](https://multipass.run/) is a [CLI](https://multipass.run/docs/multipass-cli-commands) from Canonical for managing Ubuntu VMs.

### Setup

It's recommended to **start all the commands in "Nix dev shell"**, which can be started with `nix develop` command.

 - `%` indicates a command ran in your macOS environment
 - `$` indicates a command ran inside the Ubuntu VM
 - `#` indicates a comment
 
```shell
% brew install --cask multipass
# pick appropriate resource allocation for your device, disk should be >= 20G
% multipass launch 22.04 --name fedidev --cpus 8 --mem 6G --disk 20G 
% multipass shell fedidev
$ sudo apt-get install build-essential
$ sh <(curl -L https://nixos.org/nix/install) --daemon
$ echo "experimental-features = nix-command flakes" | sudo tee -a /etc/nix/nix.conf
$ sudo systemctl restart nix-daemon
$ exec "$SHELL"
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ git clone https://github.com/fedimint/fedimint
$ cd fedimint
$ nix develop
$ ./scripts/tmuxinator.sh
# you should now have a fully setup federation with all the backing bitcoin infrastructure running locally
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

# Development Container

Some modern IDEs can use docker containers as development environments. Which means that anyone can quickly get started with development in a predictable isolated environment.

This project includes a development container which has been tested with [VSCode](https://code.visualstudio.com). More information on VSCode development containers can be found [here](https://code.visualstudio.com/docs/remote/containers). More information on this project's development container can be found [here](../.devcontainer/README.md).

To get started, simply open the project with VSCode and follow its prompt to use the development container. You may also wish to consider [these](https://code.visualstudio.com/docs/remote/containers#_installation) instructions.
