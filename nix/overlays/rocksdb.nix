final: prev: {

  rocksdb = prev.rocksdb.overrideAttrs (oldAttrs: rec {
    version = "8.10.2";

    src = final.fetchFromGitHub {
      owner = "facebook";
      repo = oldAttrs.pname;
      rev = "v${version}";
      hash = "sha256-96c1coG2euj8yWpSr3MYPEjxfo/7wuQgk0G+UBr3m0Q=";
    };
  });
}
