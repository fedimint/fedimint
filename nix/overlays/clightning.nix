final: prev: {
  clightning = prev.clightning.overrideAttrs (oldAttrs: rec {
    version = "24.08.1";
    src = prev.fetchurl {
      url = "https://github.com/ElementsProject/lightning/releases/download/v${version}/clightning-v${version}.zip";
      sha256 = "sha256-2ZKvhNuzGftKwSdmMkHOwE9UEI5Ewn5HHSyyZUcCwB4=";
    };
    makeFlags = [ "VERSION=v${version}" ];
    configureFlags = [ "--disable-valgrind" ];
    env = {
      NIX_CFLAGS_COMPILE = "-w";
    };
    postInstall = "";
  });
}
