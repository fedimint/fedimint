### Working with Nix

Clone the repository:
```
git clone git@github.com:fedimint/minimint.git
```
Enter development shell: 
```
nix-shell
```
Setup development environment locally:
```
nix-build default.nix
```
Run integration tests with nix-shell:
```
nix-shell --command ./scripts/integrationtest.sh
```

### nix-flakes:

Minimint can be installed using nix-flakes by running: 
```
nix run github:fedimint/minimint
```
To build a specific branch:
```
nix run github:fedimint/minimint/branch_name
```