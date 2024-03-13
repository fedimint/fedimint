final: prev: {

  rocksdb = prev.rocksdb.overrideAttrs (oldAttrs: rec {
    version = "8.10.0";

    src = final.fetchFromGitHub {
      owner = "facebook";
      repo = oldAttrs.pname;
      rev = "v${version}";
      hash = "sha256-KGsYDBc1fz/90YYNGwlZ0LUKXYsP1zyhP29TnRQwgjQ=";
    };
  });
}
