### Working with Nix

These are the [official docs](https://nix.dev/tutorials/install-nix)

To install nix:
```shell
sh <(curl -L https://nixos.org/nix/install) --no-daemon
```

To install nix on macOS:
```shell
sh <(curl -L https://nixos.org/nix/install) --darwin-use-unencrypted-nix-store-volume --daemon
```

Clone the repository:
```
git clone git@github.com:fedimint/minimint.git
```
Enter development shell: 
```nix
nix-shell
```
Setup development environment locally:
```nix
nix-build default.nix
```
Run integration tests with nix-shell:
```nix
nix-shell --command ./scripts/integrationtest.sh
```

### nix-flakes:

Minimint can be installed without cloning the repository using nix-flakes by running: 
```nix
nix run github:fedimint/minimint
```
To build a specific branch:
```nix
nix run github:fedimint/minimint/branch_name
```
