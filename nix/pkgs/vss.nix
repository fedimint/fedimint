{ lib, stdenv, fetchFromGitHub, openjdk, gradle, makeWrapper }:

stdenv.mkDerivation rec {
  pname = "vss-server";
  version = "main";

  src = fetchFromGitHub {
    owner = "lightningdevkit";
    repo = "vss-server";
    rev = "main";
    sha256 = "sha256-RGcYJxFk22/Pb7aRxZs4XPAR8LAdcd3YLRdun8jnHsQ=";
  };

  nativeBuildInputs = [ gradle makeWrapper ];
  buildInputs = [ openjdk ];

  buildPhase = ''
    runHook preBuild
    export JAVA_HOME=${openjdk}
    # Build in the specified buildDir
    cd java/app
    ${gradle}/bin/gradle build -Pspring.profiles.active=memory --offline
    runHook postBuild
  '';

  installPhase = ''
    mkdir -p $out/bin $out/lib
    cp build/libs/*.war $out/lib/vss-server.war
    makeWrapper ${openjdk}/bin/java $out/bin/vss-server \
      --add-flags "-jar $out/lib/vss-server.war --spring.profiles.active=memory --bind-addr=0.0.0.0:8080"
  '';

  meta = with lib; {
    description = "Versioned Storage Service (VSS) server for LDK (in-memory backend)";
    homepage = "https://github.com/lightningdevkit/vss-server";
    license = licenses.mit;
  };
}