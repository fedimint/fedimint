{ pkgs, pkgs-unstable, pkgs-kitman, flakeboxLib, toolchains, advisory-db, profiles, craneMultiBuild, replaceGitHash }:
let
  lib = pkgs.lib;

  # `moreutils/bin/parallel` and `parallel/bin/parallel` conflict, so just use
  # the binary we need from `moreutils`
  moreutils-ts = pkgs.writeShellScriptBin "ts" "exec ${pkgs.moreutils}/bin/ts \"$@\"";

  # placeholder we use to avoid actually needing to detect hash via running `git`
  # 012345... for easy recognizability (in case something went wrong),
  # rest randomized to avoid accidentally overwriting innocent bytes in the binary
  gitHashPlaceholderValue = "01234569abcdef7afa1d2683a099c7af48a523c1";

  filterWorkspaceDepsBuildFilesRegex = [ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".config" ".config/.*" ".*/Cargo.toml" ".*/proto/.*" ];

  commonSrc = builtins.path { path = ./..; name = "fedimint"; };

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
  filterWorkspaceDepsBuildFiles = src: filterSrcWithRegexes filterWorkspaceDepsBuildFilesRegex src;

  # Filter only files relevant to building the workspace
  filterWorkspaceBuildFiles = src: filterSrcWithRegexes (filterWorkspaceDepsBuildFilesRegex ++ [ ".*\.rs" ".*\.html" ".*/proto/.*" "db/migrations/.*" "devimint/src/cfg/.*" ]) src;

  # Like `filterWorkspaceFiles` but with `./scripts/` included
  filterWorkspaceTestFiles = src: filterSrcWithRegexes (filterWorkspaceDepsBuildFilesRegex ++ [ ".*\.rs" ".*\.html" ".*/proto/.*" "db/migrations/.*" "devimint/src/cfg/.*" "scripts/.*" ]) src;

  filterWorkspaceAuditFiles = src: filterSrcWithRegexes (filterWorkspaceDepsBuildFilesRegex ++ [ "deny.toml" ]) src;

  # env vars for linking rocksdb
  commonEnvsShellRocksdbLink =
    let
      target_underscores = lib.strings.replaceStrings [ "-" ] [ "_" ] pkgs.stdenv.buildPlatform.config;
    in
    {
      ROCKSDB_STATIC = "true";
      ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib/";
      SNAPPY_LIB_DIR = "${pkgs.pkgsStatic.snappy}/lib/";

      "ROCKSDB_${target_underscores}_STATIC" = "true";
      "ROCKSDB_${target_underscores}_LIB_DIR" = "${pkgs.rocksdb}/lib/";
      "SNAPPY_${target_underscores}_LIB_DIR" = "${pkgs.pkgsStatic.snappy}/lib/";
    } // pkgs.lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
      # macos can't static libraries
      SNAPPY_STATIC = "true";
      "SNAPPY_${target_underscores}_STATIC" = "true";
    };

  commonEnvsShellRocksdbLinkCross = commonEnvsShellRocksdbLink // pkgs.lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
    # TODO: could we used the android-nixpkgs toolchain instead of another one?
    # ROCKSDB_aarch64_linux_android_STATIC = "true";
    # SNAPPY_aarch64_linux_android_STATIC = "true";
    # ROCKSDB_aarch64_linux_android_LIB_DIR = "${pkgs-unstable.pkgsCross.aarch64-android-prebuilt.rocksdb}/lib/";
    # SNAPPY_aarch64_linux_android_LIB_DIR = "${pkgs-unstable.pkgsCross.aarch64-android-prebuilt.pkgsStatic.snappy}/lib/";

    # BROKEN
    # error: "No timer implementation for this platform"
    # ROCKSDB_armv7_linux_androideabi_STATIC = "true";
    # SNAPPY_armv7_linux_androideabi_STATIC = "true";
    # ROCKSDB_armv7_linux_androideabi_LIB_DIR = "${pkgs-unstable.pkgsCross.armv7a-android-prebuilt.rocksdb}/lib/";
    # SNAPPY_armv7_linux_androideabi_LIB_DIR = "${pkgs-unstable.pkgsCross.armv7a-android-prebuilt.pkgsStatic.snappy}/lib/";

    # x86-64-linux-android doesn't have a toolchain in nixpkgs
  } // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
    # broken: fails to compile with:
    # `linux-headers-android-common> sh: line 1: gcc: command not found`
    # ROCKSDB_aarch64_linux_android_STATIC = "true";
    # SNAPPY_aarch64_linux_android_STATIC = "true";
    # ROCKSDB_aarch64_linux_android_LIB_DIR = "${pkgs-unstable.pkgsCross.aarch64-android.rocksdb}/lib/";
    # SNAPPY_aarch64_linux_android_LIB_DIR = "${pkgs-unstable.pkgsCross.aarch64-android.pkgsStatic.snappy}/lib/";

    # requires downloading Xcode manually and adding to /nix/store
    # then running with `env NIXPKGS_ALLOW_UNFREE=1 nix develop -L --impure`
    # maybe we could live with it?
    # ROCKSDB_aarch64_apple_ios_STATIC = "true";
    # SNAPPY_aarch64_apple_ios_STATIC = "true";
    # ROCKSDB_aarch64_apple_ios_LIB_DIR = "${pkgs-unstable.pkgsCross.iphone64.rocksdb}/lib/";
    # SNAPPY_aarch64_apple_ios_LIB_DIR = "${pkgs-unstable.pkgsCross.iphone64.pkgsStatic.snappy}/lib/";
  };

  # env variables we want to set in all nix derivations & nix develop shell
  commonEnvsShell = commonEnvsShellRocksdbLink // {
    PROTOC = "${pkgs.protobuf}/bin/protoc";
    PROTOC_INCLUDE = "${pkgs.protobuf}/include";
  };

  # env variables we want to set in all nix derivations (but NOT the nix develop shell)
  commonEnvsBuild = commonEnvsShell // {
    FEDIMINT_BUILD_FORCE_GIT_HASH = gitHashPlaceholderValue;
    HOME = "/tmp";
  };

  commonArgs = {
    pname = "fedimint";

    buildInputs = with pkgs; [
      openssl
      pkg-config
      protobuf
    ] ++ lib.optionals (!stdenv.isDarwin) [
      util-linux
      iproute2
    ] ++ lib.optionals stdenv.isDarwin [
      libiconv
      darwin.apple_sdk.frameworks.Security
    ] ++ builtins.attrValues {
      inherit (pkgs) openssl;
    };

    nativeBuildInputs = with pkgs; [
      pkg-config
      moreutils-ts

      # tests
      (hiPrio pkgs.bashInteractive)
      bc
      bitcoind
      clightning
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
    ] ++ builtins.attrValues {
      inherit (pkgs) cargo-nextest;
    };

    # we carefully optimize our debug symbols on cargo level,
    # and in case of errors and panics, would like to see the
    # line numbers etc.
    dontStrip = true;
  };

  commonCliTestArgs = commonArgs // {
    pname = "fedimint-test";
    # there's no point saving the `./target/` dir
    doInstallCargoArtifacts = false;
    # the build command will be the test
    doCheck = true;
  };

in
(flakeboxLib.craneMultiBuild { inherit toolchains profiles; }) (craneLib':
let
  craneLib =
    (craneLib'.overrideArgs (commonEnvsBuild // commonArgs // {
      src = filterWorkspaceBuildFiles commonSrc;
      pname = "fedimint";
      version = "0.1.0";
    })).overrideArgs'' (craneLib: args:
      pkgs.lib.optionalAttrs (!(builtins.elem (craneLib.toolchainName or null) [ null "default" "stable" "nightly" ])) commonEnvsShellRocksdbLinkCross
    );

  craneLibTests = craneLib.overrideArgs (commonEnvsBuild // commonCliTestArgs // {
    src = filterWorkspaceTestFiles commonSrc;
    # there's no point saving the `./target/` dir
    doInstallCargoArtifacts = false;
  });


  fedimintBuildPackageGroup = args: replaceGitHash {
    name = args.pname;
    package =
      craneLib.buildPackageGroup args;
    placeholder = gitHashPlaceholderValue;
  };
in
rec {
  inherit commonArgs;
  inherit commonEnvsShell;
  inherit commonEnvsShellRocksdbLink;
  inherit commonEnvsShellRocksdbLinkCross;
  inherit gitHashPlaceholderValue;
  commonArgsBase = commonArgs;

  workspaceDeps = craneLib.buildWorkspaceDepsOnly {
    buildPhaseCargoCommand = "cargoWithProfile doc --locked ; cargoWithProfile check --all-targets --locked ; cargoWithProfile build --locked --all-targets";
  };
  workspaceBuild = craneLib.buildWorkspace {
    cargoArtifacts = workspaceDeps;
    buildPhaseCargoCommand = "cargoWithProfile doc --locked ; cargoWithProfile check --all-targets --locked ; cargoWithProfile build --locked --all-targets";
  };

  workspaceTest = craneLib.cargoNextest {
    cargoArtifacts = workspaceBuild;
    cargoExtraArgs = "--workspace --all-targets --locked";

    FM_CARGO_DENY_COMPILATION = "1";
  };

  workspaceTestDoc = craneLib.cargoTest {
    # can't use nextest due to: https://github.com/nextest-rs/nextest/issues/16
    cargoTestExtraArgs = "--doc";
    cargoArtifacts = workspaceBuild;

    # workaround: `cargo test --doc` started to ignore CARGO_TARGET_<native-target>_RUSTFLAGS
    # out of the blue
    stdenv = pkgs.clangStdenv;
  };

  workspaceClippy = craneLib.cargoClippy {
    cargoArtifacts = workspaceDeps;

    cargoClippyExtraArgs = "--workspace --all-targets --no-deps -- --deny warnings --allow deprecated";
    doInstallCargoArtifacts = false;
  };

  workspaceDoc = craneLib.mkCargoDerivation {
    pnameSuffix = "-workspace-docs";
    cargoArtifacts = workspaceDeps;
    preConfigure = ''
      export RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links -D warnings'
    '';
    buildPhaseCargoCommand = "cargo doc --workspace --no-deps --document-private-items";
    doInstallCargoArtifacts = false;
    postInstall = ''
      cp -a target/doc/ $out
    '';
    doCheck = false;
  };

  # version of `workspaceDocs` with some nightly-only flags to publish
  workspaceDocExport = craneLib.mkCargoDerivation {
    # no need for inheriting any artifacts, as we are using it as a one-off, and only care
    # about the docs
    cargoArtifacts = null;
    preConfigure = ''
      export RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links -Z unstable-options --enable-index-page -D warnings'
    '';
    buildPhaseCargoCommand = "cargo doc --workspace --no-deps --document-private-items";
    doInstallCargoArtifacts = false;
    installPhase = ''
      cp -a target/doc/ $out
    '';
    doCheck = false;
  };

  workspaceCargoUdepsDeps = craneLib.buildDepsOnly {
    pname = "${commonArgs.pname}-udeps-deps";
    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.cargo-udeps ];
    # since we filtered all the actual project source, everything will definitely fail
    # but we only run this step to cache the build artifacts, so we ignore failure with `|| true`
    buildPhaseCargoCommand = "cargo udeps --workspace --all-targets --profile $CARGO_PROFILE || true";
    doCheck = false;
  };

  workspaceCargoUdeps = craneLib.mkCargoDerivation {
    pname = "fedimint-udeps";
    # no need for inheriting any artifacts, as we are using it as a one-off, and only care
    # about the docs
    cargoArtifacts = workspaceCargoUdepsDeps;
    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.cargo-udeps ];
    buildPhaseCargoCommand = "cargo udeps --workspace --all-targets --profile $CARGO_PROFILE";
    doInstallCargoArtifacts = false;
    doCheck = false;
  };

  cargoAudit = craneLib.cargoAudit {
    inherit advisory-db;
    src = filterWorkspaceAuditFiles commonSrc;
  };

  cargoDeny = craneLib.cargoDeny {
    src = filterWorkspaceAuditFiles commonSrc;
  };

  # Build only deps, but with llvm-cov so `workspaceCov` can reuse them cached
  workspaceDepsCov = craneLib.buildDepsOnly {
    pname = "fedimint-workspace-lcov";
    buildPhaseCargoCommand = "source <(cargo llvm-cov show-env --export-prefix); cargo build --locked --workspace --all-targets --profile $CARGO_PROFILE";
    cargoBuildCommand = "dontuse";
    cargoCheckCommand = "dontuse";
    nativeBuildInputs = [ pkgs.cargo-llvm-cov ];
    doCheck = false;
  };

  workspaceCov = craneLib.buildPackage {
    pname = "fedimint-workspace-lcov";
    cargoArtifacts = workspaceDepsCov;
    buildPhaseCargoCommand = "source <(cargo llvm-cov show-env --export-prefix); cargo build --locked --workspace --all-targets --profile $CARGO_PROFILE; env RUST_BACKTRACE=1 RUST_LOG=info,timing=debug cargo nextest run --locked --workspace --all-targets --cargo-profile $CARGO_PROFILE --profile $CARGO_PROFILE --test-threads=$(($(nproc) * 2)); mkdir -p $out ; cargo llvm-cov report --profile $CARGO_PROFILE --lcov --output-path $out/lcov.info";
    installPhaseCommand = "true";
    nativeBuildInputs = [ pkgs.cargo-llvm-cov ];
    doCheck = false;
  };

  reconnectTest = craneLibTests.mkCargoDerivation {
    pname = "${commonCliTestArgs.pname}-reconnect";
    cargoArtifacts = workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/tests/reconnect-test.sh";
  };

  latencyTest = craneLibTests.mkCargoDerivation {
    pname = "${commonCliTestArgs.pname}-latency";
    cargoArtifacts = workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/tests/latency-test.sh";
  };

  devimintCliTest = craneLibTests.mkCargoDerivation {
    pname = "${commonCliTestArgs.pname}-cli";
    cargoArtifacts = workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/tests/devimint-cli-test.sh";
  };

  devimintCliTestSingle = craneLibTests.mkCargoDerivation {
      pname = "${commonCliTestArgs.pname}-cli";
      cargoArtifacts = workspaceBuild;
      buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/tests/devimint-cli-test-single.sh";
    };

  cliLoadTestToolTest = craneLibTests.mkCargoDerivation {
    pname = "${commonCliTestArgs.pname}-cli";
    cargoArtifacts = workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/tests/load-test-tool-test.sh";
  };

  backendTest = craneLibTests.mkCargoDerivation {
    pname = "${commonCliTestArgs.pname}-backend-test";
    cargoArtifacts = workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/test/backend-test.sh";
  };

  ciTestAll = craneLibTests.mkCargoDerivation {
    pname = "${commonCliTestArgs.pname}-all";
    cargoArtifacts = workspaceBuild;
    # One normal run, then if succeeded, modify the "always success test" to fail,
    # and make sure we detect it (happened too many times that we didn't).
    # Thanks to early termination, this should be all very quick, as we actually
    # won't start other tests.
    buildPhaseCargoCommand = ''
      patchShebangs ./scripts
      export FM_CARGO_DENY_COMPILATION=1
      ./scripts/tests/test-ci-all.sh || exit 1
      sed -i -e 's/exit 0/exit 1/g' scripts/tests/always-success-test.sh
      echo "Verifying failure detection..."
      ./scripts/tests/test-ci-all.sh 1>/dev/null 2>/dev/null && exit 1
    '';
  };

  alwaysFailTest = craneLibTests.mkCargoDerivation {
    pname = "${commonCliTestArgs.pname}-always-fail";
    cargoArtifacts = workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/tests/always-fail-test.sh";
  };


  wasmTest = craneLibTests.mkCargoDerivation {
    pname = "wasm-test";
    # TODO: https://github.com/ipetkov/crane/issues/416
    cargoArtifacts = craneMultiBuild.${craneLib.cargoProfile or "release"}.workspaceBuild;
    nativeBuildInputs = commonCliTestArgs.nativeBuildInputs ++ [ pkgs.firefox pkgs.wasm-bindgen-cli pkgs.geckodriver pkgs.wasm-pack ];
    buildPhaseCargoCommand = "patchShebangs ./scripts; SKIP_CARGO_BUILD=1 ./scripts/tests/wasm-test.sh";
  };

  fedimint-pkgs = fedimintBuildPackageGroup {
    pname = "fedimint-pkgs";

    packages = [
      "fedimintd"
      "fedimint-cli"
      "fedimint-dbtool"
    ];

    defaultBin = "fedimintd";
  };

  gateway-pkgs = fedimintBuildPackageGroup {
    pname = "gateway-pkgs";

    packages = [
      "fedimint-ln-gateway"
      "fedimint-gateway-cli"
    ];
  };

  client-pkgs = fedimintBuildPackageGroup {
    pname = "client-pkgs";

    packages = [
      "fedimint-client"
    ];
  };

  devimint = fedimintBuildPackageGroup {
    pname = "devimint";
    packages = [
      "devimint"
    ];
  };

  fedimint-load-test-tool = fedimintBuildPackageGroup {
    pname = "fedimint-load-test-tool";
    packages = [ "fedimint-load-test-tool" ];
  };


  fedimintd = flakeboxLib.pickBinary
    {
      pkg = fedimint-pkgs;
      bin = "fedimintd";
    };

  fedimint-cli = flakeboxLib.pickBinary
    {
      pkg = fedimint-pkgs;
      bin = "fedimint-cli";
    };
  fedimint-dbtool = flakeboxLib.pickBinary
    {
      pkg = fedimint-pkgs;
      bin = "fedimint-dbtool";
    };
  gatewayd = flakeboxLib.pickBinary
    {
      pkg = gateway-pkgs;
      bin = "gatewayd";
    };
  gateway-cli = flakeboxLib.pickBinary
    {
      pkg = gateway-pkgs;
      bin = "gateway-cli";
    };

  container =
    let
      entrypointScript =
        pkgs.writeShellScriptBin "entrypoint" ''
          exec bash "${../misc/fedimintd-container-entrypoint.sh}" "$@"
        '';
    in
    {
      fedimintd = pkgs.dockerTools.buildLayeredImage {
        name = "fedimintd";
        contents = [
          fedimint-pkgs
          pkgs.bash
          pkgs.coreutils
        ];
        config = {
          Cmd = [ ]; # entrypoint will handle empty vs non-empty cmd
          Env = [
            "FM_DATA_DIR=/data"
          ];
          Entrypoint = [
            "${entrypointScript}/bin/entrypoint"
          ];
          WorkDir = "/data";
          Volumes = {
            "/data" = { };
          };
          ExposedPorts = {
            "${builtins.toString 8173}/tcp" = { };
            "${builtins.toString 8174}/tcp" = { };
          };
        };
      };

      fedimint-cli = pkgs.dockerTools.buildLayeredImage {
        name = "fedimint-cli";
        contents = [ fedimint-pkgs pkgs.bash pkgs.coreutils ];
        config = {
          Cmd = [
            "${fedimint-pkgs}/bin/fedimint-cli"
          ];
        };
      };

      gatewayd = pkgs.dockerTools.buildLayeredImage {
        name = "gatewayd";
        contents = [ gateway-pkgs pkgs.bash pkgs.coreutils ];
        config = {
          Cmd = [
            "${gateway-pkgs}/bin/gatewayd"
          ];
        };
      };

      gateway-cli = pkgs.dockerTools.buildLayeredImage {
        name = "gateway-cli";
        contents = [ gateway-pkgs pkgs.bash pkgs.coreutils ];
        config = {
          Cmd = [
            "${gateway-pkgs}/bin/gateway-cli"
          ];
        };
      };

      devtools =
        pkgs.dockerTools.buildLayeredImage
          {
            name = "fedimint-devtools";
            contents = [ devimint fedimint-dbtool fedimint-load-test-tool pkgs.bash pkgs.coreutils ];
            config = {
              Cmd = [
                "${pkgs.bash}/bin/bash"
              ];
            };
          };
    };
})
