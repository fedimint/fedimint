FROM nixos/nix
ADD . .
RUN nix-channel --update
CMD nix-build default.nix