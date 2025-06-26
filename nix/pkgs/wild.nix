{
  lib,
  fetchFromGitHub,
  rustPlatform,
  pkg-config,
}:

rustPlatform.buildRustPackage rec {
  name = "wild-${version}";
  version = "0.5.0";

  src = fetchFromGitHub {
    owner = "davidlattimore";
    repo = "wild";
    rev = "81d9c116f42c232769807e0e003eac7e70f95b6e";
    sha256 = "sha256-tVGvSd4aege3xz/CrEl98AwuEJlsM3nVVG0urTSajFQ=";
  };

  doCheck = false;

  buildInputs = [
    pkg-config
  ];

  cargoHash = "sha256-dXIYJfjz6okiLJuX4ZHu0Ft2/9XDjCrvvl/eqeuvBkU=";

  meta = with lib; {
    description = "A very fast linker for Linux";
    homepage = "https://github.com/davidlattimore/wild";
    license = licenses.mit;
    maintainers = with maintainers; [ dpc ];
    platforms = platforms.linux;
  };
}
