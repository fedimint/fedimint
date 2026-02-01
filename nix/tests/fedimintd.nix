# NixOS VM test for the fedimintd module
#
# This test verifies that the fedimintd service can start successfully.
{
  pkgs,
  fedimintdModule,
  fedimintdPackage,
}:

pkgs.testers.runNixOSTest {
  name = "fedimintd";

  nodes.machine =
    { ... }:
    {
      imports = [ fedimintdModule ];

      # Disable the upstream nixpkgs module to avoid conflicts
      disabledModules = [ "services/networking/fedimintd.nix" ];

      services.fedimintd."mainnet" = {
        enable = true;
        package = fedimintdPackage;
        p2p = {
          url = "fedimint://example.com:8173";
        };
        api_ws = {
          url = "wss://example.com";
        };
        bitcoin = {
          network = "signet";
          esploraUrl = "https://mutinynet.com/api";
        };
        environment = { };
      };
    };

  testScript =
    { nodes, ... }:
    ''
      start_all()

      machine.wait_for_unit("fedimintd-mainnet.service")
      machine.wait_for_open_port(${toString nodes.machine.services.fedimintd.mainnet.api_ws.port})
    '';
}
