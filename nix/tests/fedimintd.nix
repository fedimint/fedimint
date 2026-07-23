# NixOS VM test for the fedimintd module
#
# This test verifies that the fedimintd service can start successfully.
{
  pkgs,
  fedimintdModule,
  fedimintdPackage,
}:

let
  fedimintdInstance = {
    enable = true;
    package = fedimintdPackage;
    passwordUi = "pass";
    passwordApi = "pass";
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

  disabledConfig =
    (import "${pkgs.path}/nixos/lib/eval-config.nix" {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        fedimintdModule
        {
          disabledModules = [ "services/networking/fedimintd.nix" ];
          services.fedimintd."mainnet" = fedimintdInstance // {
            api_iroh_next.enable = false;
          };
        }
      ];
    }).config;
  disabledEnvironment = disabledConfig.systemd.services."fedimintd-mainnet".environment;
in
pkgs.testers.runNixOSTest {
  name = "fedimintd";

  nodes.machine =
    { ... }:
    {
      imports = [ fedimintdModule ];

      # Disable the upstream nixpkgs module to avoid conflicts
      disabledModules = [ "services/networking/fedimintd.nix" ];

      services.fedimintd."mainnet" = fedimintdInstance;
    };

  testScript =
    { nodes, ... }:
    assert builtins.elem nodes.machine.services.fedimintd.mainnet.api_iroh_next.port
      nodes.machine.networking.firewall.allowedUDPPorts;
    assert disabledEnvironment.FM_IROH_NEXT_ENABLE == "false";
    assert !(disabledEnvironment ? FM_BIND_API_NEXT);
    ''
      start_all()

      machine.wait_for_unit("fedimintd-mainnet.service")
      machine.succeed(
          "systemctl show fedimintd-mainnet.service --property=Environment"
          " | grep -q 'FM_IROH_NEXT_ENABLE=true'"
      )
      machine.succeed(
          "systemctl show fedimintd-mainnet.service --property=Environment"
          " | grep -q 'FM_BIND_API_NEXT=0.0.0.0:8184'"
      )
      machine.wait_for_open_port(${toString nodes.machine.services.fedimintd.mainnet.api_ws.port})
    '';
}
