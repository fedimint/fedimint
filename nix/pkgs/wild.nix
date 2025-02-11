{
  lib,
  fetchFromGitHub,
  rustPlatform,
  pkg-config,
}:

rustPlatform.buildRustPackage rec {
  name = "wild-${version}";
  version = "0.3.0-git";

  src = fetchFromGitHub {
    owner = "davidlattimore";
    repo = "wild";
    rev = "d73f2be52184ab39c1db03be32e96dab77c69c0f";
    sha256 = "sha256-A5izko2u18UgdmHDrIGQ6hOnvzKbR/9NJ7s6CpMEw+g=";
  };

  doCheck = false;

  buildInputs = [
    pkg-config
  ];

  cargoHash = "sha256-YPRGf0dRLiMoRn6/t27a8iWUFh5NCe7iEitSK0FhJQg=";

  meta = with lib; {
    description = "A very fast linker for Linux";
    homepage = "https://github.com/davidlattimore/wild";
    license = licenses.mit;
    maintainers = with maintainers; [ dpc ];
    platforms = platforms.linux;
  };
}
