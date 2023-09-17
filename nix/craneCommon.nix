# Functionality w.r.t. common (but overridable)  Nix/crane settings like:
#
# * source file filtering
# * CARGO_PROFILE
# * build inputs
# * env variables

{ src, srcDotCargo, pkgs, lib, clightning-dev, pkgs-kitman, moreutils-ts, ... }:
craneLib:
craneLib.overrideScope' (self: prev:

let
  filterWorkspaceDepsBuildFilesRegex = [ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".config" ".config/.*" ".*/Cargo.toml" ".*/proto/.*" ];
in
{

  commonSrc = builtins.path { path = src; name = "fedimint"; };

  commonProfile = "release";
  # placeholder we use to avoid actually needing to detect hash via running `git`
  # 012345... for easy recognizability (in case something went wrong),
  # rest randomized to avoid accidentally overwriting innocent bytes in the binary
  gitHashPlaceholderValue = "01234569abcdef7afa1d2683a099c7af48a523c1";

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
  filterWorkspaceDepsBuildFiles = src: self.filterSrcWithRegexes filterWorkspaceDepsBuildFilesRegex src;

  # Filter only files relevant to building the workspace
  filterWorkspaceFiles = src: self.filterSrcWithRegexes (filterWorkspaceDepsBuildFilesRegex ++ [ ".*\.rs" ".*\.html" ".*/proto/.*" "db/migrations/.*" "devimint/src/cfg/.*" ]) src;

  # Like `filterWorkspaceFiles` but with `./scripts/` included
  filterWorkspaceTestFiles = src: self.filterSrcWithRegexes (filterWorkspaceDepsBuildFilesRegex ++ [ ".*\.rs" ".*\.html" ".*/proto/.*" "db/migrations/.*" "devimint/src/cfg/.*" "scripts/.*" ]) src;

  # env variables we want to set in all nix derivations & nix develop shell
  commonEnvsShell = {
    LIBCLANG_PATH = "${pkgs.libclang.lib}/lib/";
    ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib/";
    PROTOC = "${pkgs.protobuf}/bin/protoc";
    PROTOC_INCLUDE = "${pkgs.protobuf}/include";
    CARGO_PROFILE = self.commonProfile;
  };

  # env variables we want to set in all nix derivations (but NOT the nix develop shell)
  commonEnvs = self.commonEnvsShell // {
    FEDIMINT_BUILD_FORCE_GIT_HASH = self.gitHashPlaceholderValue;
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
      cargo-nextest
      moreutils-ts
      parallel
    ];

    # we carefully optimize our debug symbols on cargo level,
    # and in case of errors and panics, would like to see the
    # line numbers etc.
    dontStrip = !pkgs.stdenv.isDarwin;


    # https://github.com/ipetkov/crane/issues/76#issuecomment-1296025495
    installCargoArtifactsMode = "use-symlink";

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
