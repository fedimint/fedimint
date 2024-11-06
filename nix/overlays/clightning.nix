final: prev: {
  clightning = prev.clightning.overrideAttrs (oldAttrs: rec {
    version = "23.05.2";
    src = prev.fetchurl {
      url = "https://github.com/ElementsProject/lightning/releases/download/v${version}/clightning-v${version}.zip";
      sha256 = "sha256-Tj5ybVaxpk5wmOw85LkeU4pgM9NYl6SnmDG2gyXrTHw=";
    };
    makeFlags = [ "VERSION=v${version}" ];
    configureFlags = [
      "--enable-developer"
      "--disable-valgrind"
    ];
    env = {
      NIX_CFLAGS_COMPILE = "-w";
    };
    postInstall = "";
  });
}
