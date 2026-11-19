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

  evaluatedConfig =
    (import "${pkgs.path}/nixos/lib/eval-config.nix" {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        fedimintdModule
        ({ lib, ... }: {
          disabledModules = [ "services/networking/fedimintd.nix" ];
          system.stateVersion = "26.05";
          services.nginx = {
            enable = true;
            enableReload = true;
            virtualHosts."manual.example.com".enableACME = lib.mkForce false;
          };
          security.acme.acceptTerms = true;
          security.acme.defaults.email = "admin@example.com";
          services.fedimintd = {
            mainnet = fedimintdInstance // {
              api_iroh_next.enable = false;
              bitcoin = {
                bitcoindUrl = "http://127.0.0.1:38332";
              };
              environment.FM_ESPLORA_URL = "https://mutinynet.com/api";
              nginx = {
                enable = true;
                fqdn = "example.com";
              };
            };
            manual = fedimintdInstance // {
              nginx = {
                enable = true;
                fqdn = "manual.example.com";
                config = {
                  sslCertificate = "/var/lib/certs/manual.crt";
                  sslCertificateKey = "/var/lib/certs/manual.key";
                };
              };
            };
          };
        })
      ];
    }).config;
  disabledEnvironment = evaluatedConfig.systemd.services."fedimintd-mainnet".environment;
  acmeOverrides = evaluatedConfig.services.fedimintd.mainnet.nginx.config;
  manualVhost = evaluatedConfig.services.nginx.virtualHosts."manual.example.com";
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
    assert disabledEnvironment.FM_BITCOIND_URL == "http://127.0.0.1:38332";
    assert disabledEnvironment.FM_ESPLORA_URL == "https://mutinynet.com/api";
    assert !(disabledEnvironment ? FM_BITCOIND_PASSWORD);
    assert acmeOverrides.sslCertificate == null;
    assert acmeOverrides.sslCertificateKey == null;
    assert manualVhost.sslCertificate == "/var/lib/certs/manual.crt";
    assert manualVhost.sslCertificateKey == "/var/lib/certs/manual.key";
    assert evaluatedConfig.environment.etc."nginx/nginx.conf".source.drvPath != "";
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
