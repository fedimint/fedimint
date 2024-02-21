final: prev: {
  # syncing channels doesn't work right on newer versions, exactly like described here
  # https://bitcoin.stackexchange.com/questions/84765/how-can-channel-policy-be-missing
  # note that config-time `--enable-developer` turns into run-time `--developer` at some
  # point
  clightning = prev.clightning.overrideAttrs (oldAttrs: rec {
    version = "23.05.2";
    src = prev.fetchurl {
      url = "https://github.com/ElementsProject/lightning/releases/download/v${version}/clightning-v${version}.zip";
      sha256 = "sha256-Tj5ybVaxpk5wmOw85LkeU4pgM9NYl6SnmDG2gyXrTHw=";
    };
    makeFlags = [ "VERSION=v${version}" ];
    configureFlags = [ "--enable-developer" "--disable-valgrind" ];
    NIX_CFLAGS_COMPILE = "-w";
  });
}
