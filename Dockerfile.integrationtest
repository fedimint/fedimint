FROM nixos/nix
ADD . .
RUN nix-channel --update
CMD nix-shell --command ./scripts/integrationtest.sh