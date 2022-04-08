{ lib, rustPlatform, fetchFromGitHub}:

rustPlatform.buildRustPackage rec {
  pname = "minimint";
  version = "master";

  checkType = "debug";
  src = builtins.fetchGit {
  url = "https://github.com/fedimint/minimint";
  ref = "master";
  };

  cargoSha256 =  "sha256-YhyJ8CGck66fHMfADc+TV05mvufB8mMh/01wxvKNjLs=";
  meta = with lib; {
    description = "Federated Mint Prototype";
    homepage = "https://github.com/fedimint/minimint";
    license = licenses.mit;
    maintainers = with maintainers; [  ];
  };
}
