{ lib, rustPlatform, fetchFromGitHub}:

rustPlatform.buildRustPackage rec {
  pname = "minimint";
  version = "master";

  checkType = "debug";
  src = builtins.fetchGit {
  url = "https://github.com/fedimint/minimint";
  ref = "master";
  };

  cargoSha256 =  "sha256-1lZElXK9M895DURLID2KJdmCkJRTFNVC3meLFluO2WU=";
  meta = with lib; {
    description = "Federated Mint Prototype";
    homepage = "https://github.com/fedimint/minimint";
    license = licenses.mit;
    maintainers = with maintainers; [  ];
  };
}
