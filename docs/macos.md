# How to get started with developing Fedimint on macOS

macOS is different than Linux in many meaningful ways, as a result following what Linux users do will not work.

This guide is meant to help you get started developing fedimint on your macOS device;
 - this has been shown to work with `macOS Monterey` on `aarch64` aka Apple Silicon (as opposed to `x86_64`, aka Intel - if these steps dont work for Intel and there is interest in running with Intel, then please make an issue)
 - this guide uses `multipass`, a virtualization method provided by Canonical
 - `multipass` can be replaced with any other means of running a VM on your local device, `multipass` is showcased due to ease-of-use

# Prerequisites 

 - spend lots of money on new mac thinking it will help you get more work done
 - be upset that Apple makes it a pain in the neck to get work done in a sane way
 - lament lack of sats
 - justify lack of sats by thinking that runing MSoffice, using bluetooth headphones and connecting to projectors with ease is totally worth it
 - realize its not and that you are bad at making financial decisions
 - install homebrew on macOS
 
# Instructions

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

# Next steps
 - use [VScode to ssh remotely](https://dev.to/josuebustos/vs-code-remote-ssh-multipass-dn8)
 - IntelliJ also has this feature
 - using shell based text editors (vi, emacs or nano) allows you to avoid using SSH altogether

