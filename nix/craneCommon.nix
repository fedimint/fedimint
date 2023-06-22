# Functionality w.r.t. common (but overridable)  Nix/crane settings like:
#
# * source file filtering
# * CARGO_PROFILE
# * build inputs
# * env variables

{ src, srcDotCargo, pkgs, lib, clightning-dev, pkgs-kitman, moreutils-ts, ... }:
craneLib:
craneLib.overrideScope' (self: prev: {

  commonSrc = builtins.path { path = src; name = "fedimint"; };

  commonProfile = "release";

  filterSrcWithRegexes = regexes: src:
    let
      basePath = toString src + "/";
    in
    lib.cleanSourceWith {
      filter = (path: type:
        let
          relPath = lib.removePrefix basePath (toString path);
          includePath =
            (type == "directory") ||
            lib.any
              (re: builtins.match re relPath != null)
              regexes;
        in
        # uncomment to debug:
          # builtins.trace "${relPath}: ${lib.boolToString includePath}"
        includePath
      );
      inherit src;
    };

  # Filter only files needed to build project dependencies
  #
  # To get good build times it's vitally important to not have to
  # rebuild derivation needlessly. The way Nix caches things
  # is very simple: if any input file changed, derivation needs to
  # be rebuild.
  #
  # For this reason this filter function strips the `src` from
  # any files that are not relevant to the build.
  #
  # Lile `filterWorkspaceFiles` but doesn't even need *.rs files
  # (because they are not used for building dependencies)
  filterWorkspaceDepsBuildFiles = src: self.filterSrcWithRegexes [ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".*/Cargo.toml" ".*/proto/.*" ] src;

  # Filter only files relevant to building the workspace
  filterWorkspaceFiles = src: self.filterSrcWithRegexes [ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".*/Cargo.toml" ".*\.rs" ".*\.html" ".*/proto/.*" "db/migrations/.*" "devimint/src/cfg/.*" ] src;

  # Like `filterWorkspaceFiles` but with `./scripts/` included
  filterWorkspaceTestFiles = src: self.filterSrcWithRegexes [ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".*/Cargo.toml" ".*\.rs" ".*\.html" ".*/proto/.*" "devimint/src/cfg/.*" "scripts/.*" ] src;

  cargo-llvm-cov = self.buildPackage rec {
    pname = "cargo-llvm-cov";
    version = "0.4.14";
    buildInputs = [ ];

    src = pkgs.fetchCrate {
      inherit pname version;
      sha256 = "sha256-DY5eBSx/PSmKaG7I6scDEbyZQ5hknA/pfl0KjTNqZlo=";
    };
    doCheck = false;
  };

  commonEnvs = {
    LIBCLANG_PATH = "${pkgs.libclang.lib}/lib/";
    ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib/";
    PROTOC = "${pkgs.protobuf}/bin/protoc";
    PROTOC_INCLUDE = "${pkgs.protobuf}/include";
    CARGO_PROFILE = self.commonProfile;
    FEDIMINT_BUILD_ALLOW_GIT_FAIL = "true";
  };

  commonArgsBase = {
    pname = "fedimint";

    buildInputs = with pkgs; [
      clang
      gcc
      openssl
      pkg-config
      perl
      pkgs.llvmPackages.bintools
      rocksdb
      protobuf

      moreutils-ts
      parallel
    ] ++ lib.optionals (!stdenv.isDarwin) [
      util-linux
      iproute2
    ] ++ lib.optionals stdenv.isDarwin [
      libiconv
      darwin.apple_sdk.frameworks.Security
      zld
    ] ++ lib.optionals (!(stdenv.isAarch64 || stdenv.isDarwin)) [
      # mold is currently broken on ARM and MacOS
      mold
    ];

    nativeBuildInputs = with pkgs; [
      pkg-config
      moreutils-ts

      # tests
      (hiPrio pkgs.bashInteractive)
      bc
      bitcoind
      clightning-dev
      electrs
      jq
      lnd
      netcat
      perl
      pkgs-kitman.esplora
      procps
      which
    ];


    # https://github.com/ipetkov/crane/issues/76#issuecomment-1296025495
    installCargoArtifactsMode = "use-zstd";

    CI = "true";
    HOME = "/tmp";
  } // self.commonEnvs;

  commonArgs = self.commonArgsBase // {
    src = self.filterWorkspaceFiles self.commonSrc;
  };

  commonArgsDepsOnly = self.commonArgsBase // {
    cargoVendorDir = self.vendorCargoDeps {
      src = self.filterWorkspaceFiles self.commonSrc;
    };
    # copy over the linker/ar wrapper scripts which by default would get
    # stripped by crane
    dummySrc = self.mkDummySrc {
      src = self.filterWorkspaceDepsBuildFiles self.commonSrc;
      extraDummyScript = ''
        # temporary workaround: https://github.com/ipetkov/crane/issues/312#issuecomment-1601827484
        rm -f $(find $out | grep bin/crane-dummy/main.rs)

        cp -ar ${srcDotCargo} --no-target-directory $out/.cargo
      '';
    };
  };

  commonCliTestArgs = self.commonArgs // {
    pname = "fedimint-test";
    version = "0.0.1";
    src = self.filterWorkspaceTestFiles self.commonSrc;
    # there's no point saving the `./target/` dir
    doInstallCargoArtifacts = false;
    # the build command will be the test
    doCheck = true;
  };
})
