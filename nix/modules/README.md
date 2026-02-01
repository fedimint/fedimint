# Fedimint NixOS modules


# `fedimintd.nix`

This is [NixOS module](https://nixos.wiki/wiki/NixOS_modules) enabling `fedimintd` service(s).

Importing external modules is outside of scope of this document, but if
you are using Nix Flakes to define your system the below example can help:

```nix
  # add fedimint github url as an flake input
  inputs = {
    # ...

    fedimint = {
      url = "github:fedimint/fedimint/v0.3.0-rc.0";
    };
  };

  # add the input as an argument to the outputs
  outputs =
    { nixpkgs
    , fedimint
    }: {
      # ...
      nixosConfigurations = {

        mySystem = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            fedimint.nixosModules.fedimintd
            ./hosts/my-system.nix
          ];
        };
      };
    };
    # ...
```

After the module is imported one or more fedimintd instances can be configured with:

```
  services.fedimintd."mainnet" = {
    enable = true;
    api_ws.url = "wss://api.myfedimint.com";
    api.openFirewall = true;
    p2p.url = "fedimint://p2p.myfedimint.com";
    p2p.openFirewall = true;
  };
```

For full list of options refer to [`fedimintd.nix` module source code](./fedimintd.nix).
