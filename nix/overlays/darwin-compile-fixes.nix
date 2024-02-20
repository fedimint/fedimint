final: prev: {

  rocksdb_7_10 = prev.rocksdb_7_10.overrideAttrs (oldAttrs:
    final.lib.optionalAttrs final.stdenv.isDarwin {
      # C++ and its damn super-fragie compilation
      env = oldAttrs.env // {
        NIX_CFLAGS_COMPILE = oldAttrs.env.NIX_CFLAGS_COMPILE + " -Wno-error=unused-but-set-variable";
      };
    });

  rocksdb_6_23 = prev.rocksdb_6_23.overrideAttrs (oldAttrs:
    final.lib.optionalAttrs final.stdenv.isDarwin {
      # C++ and its damn super-fragie compilation
      env = oldAttrs.env // {
        NIX_CFLAGS_COMPILE = oldAttrs.env.NIX_CFLAGS_COMPILE + " -Wno-error=unused-but-set-variable -Wno-error=deprecated-copy";
      };
    });

  bitcoind = prev.bitcoind.overrideAttrs (oldAttrs: {
    # tests broken on Mac for some reason
    doCheck = !prev.stdenv.isDarwin;
  });

}
