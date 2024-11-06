{
  pkgs,
  flakeboxLib,
  toolchains,
  advisory-db,
  profiles,
  craneMultiBuild,
  replaceGitHash,
}:
let
  lib = pkgs.lib;

  # `moreutils/bin/parallel` and `parallel/bin/parallel` conflict, so just use
  # the binary we need from `moreutils`
  moreutils-ts = pkgs.writeShellScriptBin "ts" "exec ${pkgs.moreutils}/bin/ts \"$@\"";

  # placeholder we use to avoid actually needing to detect hash via running `git`
  # 012345... for easy recognizability (in case something went wrong),
  # rest randomized to avoid accidentally overwriting innocent bytes in the binary
  gitHashPlaceholderValue = "01234569abcdef7afa1d2683a099c7af48a523c1";

  filterWorkspaceDepsBuildFilesRegex = [
    "Cargo.lock"
    "Cargo.toml"
    ".cargo"
    ".cargo/.*"
    ".config"
    ".config/.*"
    ".*/Cargo.toml"
    ".*/proto/.*"
  ];

  commonSrc = builtins.path {
    path = ./..;
    name = "fedimint";
  };

  filterSrcWithRegexes =
    regexes: src:
    let
      basePath = toString src + "/";
    in
    lib.cleanSourceWith {
      filter = (
        path: type:
        let
          relPath = lib.removePrefix basePath (toString path);
          includePath = (type == "directory") || lib.any (re: builtins.match re relPath != null) regexes;
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
  filterWorkspaceBuildFiles =
    src:
    filterSrcWithRegexes (
      filterWorkspaceDepsBuildFilesRegex
      ++ [
        ".*\.rs"
        ".*\.html"
        ".*/proto/.*"
        "db/migrations/.*"
        "devimint/src/cfg/.*"
        "docs/.*\.md"
      ]
    ) src;

  # Like `filterWorkspaceFiles` but with `./scripts/` included
  filterWorkspaceTestFiles =
    src:
    filterSrcWithRegexes (
      filterWorkspaceDepsBuildFilesRegex
      ++ [
        ".*\.rs"
        ".*\.html"
        ".*/proto/.*"
        "db/migrations/.*"
        "devimint/src/cfg/.*"
        "scripts/.*"
        "docs/.*\.md"
      ]
    ) src;

  filterWorkspaceAuditFiles =
    src: filterSrcWithRegexes (filterWorkspaceDepsBuildFilesRegex ++ [ "deny.toml" ]) src;

  # env vars for linking rocksdb
  commonEnvsCross =
    let
      build_arch_underscores = lib.strings.replaceStrings [ "-" ] [
        "_"
      ] pkgs.stdenv.buildPlatform.config;
    in
    {
      # for cargo-deluxe
      CARGO_TARGET_SPECIFIC_ENVS = builtins.concatStringsSep "," [
        "ROCKSDB_target_STATIC"
        "ROCKSDB_target_LIB_DIR"
        "SNAPPY_target_STATIC"
        "SNAPPY_target_LIB_DIR"
        "SNAPPY_target_COMPILE"
        "SQLITE3_target_STATIC"
        "SQLITE3_target_LIB_DIR"
        "SQLCIPHER_target_STATIC"
        "SQLCIPHER_target_LIB_DIR"
      ];
    }
    // pkgs.lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
      "ROCKSDB_${build_arch_underscores}_STATIC" = "true";
      "ROCKSDB_${build_arch_underscores}_LIB_DIR" = "${pkgs.rocksdb}/lib/";

      # does not produce static lib in most versions
      "SNAPPY_${build_arch_underscores}_STATIC" = "true";
      "SNAPPY_${build_arch_underscores}_LIB_DIR" = "${pkgs.pkgsStatic.snappy}/lib/";
      # "SNAPPY_${build_arch_underscores}_COMPILE" = "true";

      "SQLITE3_${build_arch_underscores}_STATIC" = "true";
      "SQLITE3_${build_arch_underscores}_LIB_DIR" = "${pkgs.pkgsStatic.sqlite.out}/lib/";

      "SQLCIPHER_${build_arch_underscores}_LIB_DIR" = "${pkgs.pkgsStatic.sqlcipher}/lib/";
      "SQLCIPHER_${build_arch_underscores}_STATIC" = "true";
    }
    // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
      # tons of problems, just compile
      # "SNAPPY_${build_arch_underscores}_LIB_DIR" = "${pkgs.snappy}/lib/";
      "SNAPPY_${build_arch_underscores}_COMPILE" = "true";

      "SQLITE3_${build_arch_underscores}_LIB_DIR" = "${pkgs.sqlite.out}/lib/";
      "SQLCIPHER_${build_arch_underscores}_LIB_DIR" = "${pkgs.sqlcipher}/lib/";
    };

  commonEnvsCrossShell =
    commonEnvsCross
    // pkgs.lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
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
    }
    // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
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
  commonEnvsShell = commonEnvsCross // {
    PROTOC = "${pkgs.protobuf}/bin/protoc";
    PROTOC_INCLUDE = "${pkgs.protobuf}/include";
    CLIPPY_ARGS = "--deny warnings --allow deprecated";
  };

  # env variables we want to set in all nix derivations (but NOT the nix develop shell)
  commonEnvsBuild = commonEnvsShell // {
    FEDIMINT_BUILD_FORCE_GIT_HASH = gitHashPlaceholderValue;
    HOME = "/tmp";
  };

  commonArgs = {
    pname = "fedimint";

    packages = [
      # flakebox adds toolchains via `packages`, which seems to always take precedence
      # `nativeBuildInputs` in `mkShell`, so we need to add it here as well.
      (lib.hiPrio pkgs.cargo-deluxe)
    ];

    buildInputs =
      with pkgs;
      [
        openssl
        pkg-config
        protobuf
        sqlite
      ]
      ++ lib.optionals (!stdenv.isDarwin) [
        util-linux
        iproute2
      ]
      ++ lib.optionals stdenv.isDarwin [
        libiconv
        darwin.apple_sdk.frameworks.Security
        darwin.apple_sdk.frameworks.SystemConfiguration
      ];

    nativeBuildInputs =
      with pkgs;
      [
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
        esplora-electrs
        procps
        which
        cargo-nextest
        moreutils-ts
        parallel
        time
      ]
      ++ builtins.attrValues { inherit (pkgs) cargo-nextest; }
      ++ [
        # add a command that can be used to lower both CPU and IO priority
        # of a command to help make it more friendly to other things
        # potentially sharing the CI or dev machine
        (
          if pkgs.stdenv.isLinux then
            [
              pkgs.util-linux

              (pkgs.writeShellScriptBin "runLowPrio" ''
                set -euo pipefail

                cmd=()
                if ${pkgs.which}/bin/which chrt 1>/dev/null 2>/dev/null ; then
                  cmd+=(chrt -i 0)
                fi
                if ${pkgs.which}/bin/which ionice 1>/dev/null 2>/dev/null ; then
                  cmd+=(ionice -c 3)
                fi

                >&2 echo "Lowering IO priority with ''${cmd[@]}"
                exec "''${cmd[@]}" "$@"
              '')
            ]
          else
            [

              (pkgs.writeShellScriptBin "runLowPrio" ''
                exec "$@"
              '')
            ]
        )
      ]

    ;

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
(flakeboxLib.craneMultiBuild { inherit toolchains profiles; }) (
  craneLib':
  let
    craneLib =
      (craneLib'.overrideArgs (
        commonEnvsBuild // commonArgs // { src = filterWorkspaceBuildFiles commonSrc; }
      )).overrideArgs''
        (
          craneLib: args:
          pkgs.lib.optionalAttrs (
            !(builtins.elem (craneLib.toolchainName or null) [
              null
              "default"
              "stable"
              "nightly"
            ])
          ) commonEnvsCrossShell
        );

    craneLibTests = craneLib.overrideArgs (
      commonEnvsBuild
      // commonCliTestArgs
      // {
        src = filterWorkspaceTestFiles commonSrc;
        # there's no point saving the `./target/` dir
        doInstallCargoArtifacts = false;
      }
    );

    # copied and modified from flakebox, to add `runLowPrio`, due to mistake in flakebox
    rawBuildPackageGroup =
      {
        pname ? null,
        packages,
        mainProgram ? null,
        ...
      }@origArgs:
      let
        args = builtins.removeAttrs origArgs [
          "mainProgram"
          "pname"
          "packages"
        ];
        pname =
          if builtins.hasAttr "pname" origArgs then
            "${origArgs.pname}-group"
          else if builtins.hasAttr "pname" craneLib.args then
            "${craneLib.args.pname}-group"
          else
            null;
        # "--package x --package y" args passed to cargo
        pkgsArgs = lib.strings.concatStringsSep " " (builtins.map (name: "--package ${name}") packages);

        deps = craneLib.buildDepsOnly (
          args
          // (lib.optionalAttrs (pname != null) { inherit pname; })
          // {
            buildPhaseCargoCommand = "runLowPrio cargo build --profile $CARGO_PROFILE ${pkgsArgs}";
          }
        );
      in
      craneLib.buildPackage (
        args
        // (lib.optionalAttrs (pname != null) { inherit pname; })
        // {
          cargoArtifacts = deps;
          meta = {
            inherit mainProgram;
          };
          cargoBuildCommand = "runLowPrio cargo build --profile $CARGO_PROFILE";
          cargoExtraArgs = "${pkgsArgs}";
        }
      );

    fedimintBuildPackageGroup =
      args:
      replaceGitHash {
        name = args.pname;
        package =
          # ideally this should work:
          # craneLib.buildPackageGroup (args // { cargoBuildCommand = "runLowPrio cargo build --profile $CARGO_PROFILE"; });
          rawBuildPackageGroup args;
        placeholder = gitHashPlaceholderValue;
      };
  in
  rec {
    inherit commonArgs;
    inherit commonEnvsShell commonEnvsCrossShell;
    inherit gitHashPlaceholderValue;
    commonArgsBase = commonArgs;

    workspaceDeps = craneLib.buildWorkspaceDepsOnly {
      buildPhaseCargoCommand = "runLowPrio cargo doc --profile $CARGO_PROFILE --locked ; runLowPrio cargo check --profile $CARGO_PROFILE --all-targets --locked ; runLowPrio cargo build --profile $CARGO_PROFILE --locked --all-targets";
    };

    # like `workspaceDeps` but don't run `cargo doc`
    workspaceDepsNoDocs = craneLib.buildWorkspaceDepsOnly {
      buildPhaseCargoCommand = "runLowPrio cargo check --profile $CARGO_PROFILE --all-targets --locked ; runLowPrio cargo build --profile $CARGO_PROFILE --locked --all-targets";
    };

    workspaceBuild = craneLib.buildWorkspace {
      cargoArtifacts = workspaceDeps;
      buildPhaseCargoCommand = "runLowPrio cargo doc --profile $CARGO_PROFILE --locked ; runLowPrio cargo check --profile $CARGO_PROFILE --all-targets --locked ; runLowPrio cargo build --profile $CARGO_PROFILE --locked --all-targets";
    };

    workspaceDepsWasmTest = craneLib.buildWorkspaceDepsOnly {
      pname = "${commonArgs.pname}-wasm-test";
      buildPhaseCargoCommand = "runLowPrio cargo build --profile $CARGO_PROFILE --locked --tests -p fedimint-wasm-tests";
    };

    workspaceBuildWasmTest = craneLib.buildWorkspace {
      pnameSuffix = "-workspace-wasm-test";
      cargoArtifacts = workspaceDepsWasmTest;
      buildPhaseCargoCommand = "runLowPrio cargo build --profile $CARGO_PROFILE --locked --tests -p fedimint-wasm-tests";
    };

    workspaceTest = craneLib.cargoNextest {
      cargoArtifacts = workspaceBuild;
      cargoExtraArgs = "--workspace --all-targets --locked";

      FM_DISCOVER_API_VERSION_TIMEOUT = "10";
      CARGO_DENY_COMPILATION = "1";
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

      cargoClippyExtraArgs = "--workspace --all-targets --no-deps -- -D warnings";
      doInstallCargoArtifacts = false;
    };

    workspaceDoc = craneLibTests.mkCargoDerivation {
      pnameSuffix = "-workspace-docs";
      cargoArtifacts = workspaceDeps;
      buildPhaseCargoCommand = ''
        patchShebangs ./scripts
        export FM_RUSTDOC_INDEX_MD=${../docs/rustdoc-index.md}
        ./scripts/dev/build-docs.sh
      '';
      doInstallCargoArtifacts = false;
      postInstall = ''
        mkdir $out/share
        cp -a target/doc $out/share/doc
      '';
      doCheck = false;
      dontFixup = true;
      dontStrip = true;
    };

    # version of `workspaceDocs` for public consumption (uploaded to https://docs.fedimint.org/)
    workspaceDocExport = workspaceDoc.overrideAttrs (
      final: prev: {
        # we actually don't want to have docs for dependencies in exported documentation
        cargoArtifacts = workspaceDepsNoDocs;
        nativeBuildInputs = prev.nativeBuildInputs or [ ] ++ [ pkgs.pandoc ];
      }
    );

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

    cargoDeny = craneLib.cargoDeny { src = filterWorkspaceAuditFiles commonSrc; };

    # Build only deps, but with llvm-cov so `workspaceCov` can reuse them cached
    workspaceDepsCov = craneLib.buildDepsOnly {
      pname = "fedimint-workspace-lcov";
      buildPhaseCargoCommand = "source <(cargo llvm-cov show-env --export-prefix); runLowPrio cargo build --locked --workspace --all-targets --profile $CARGO_PROFILE";
      cargoBuildCommand = "dontuse";
      cargoCheckCommand = "dontuse";
      nativeBuildInputs = [ pkgs.cargo-llvm-cov ];
      doCheck = false;
    };

    workspaceCov = craneLib.buildWorkspace {
      pname = "fedimint-workspace-lcov";
      cargoArtifacts = workspaceDepsCov;
      buildPhaseCargoCommand = "source <(cargo llvm-cov show-env --export-prefix); runLowPrio cargo build --locked --workspace --all-targets --profile $CARGO_PROFILE;";
      nativeBuildInputs = [ pkgs.cargo-llvm-cov ];
      doCheck = false;
    };

    workspaceTestCovBase =
      { times }:
      craneLib.buildPackage {
        pname = "fedimint-workspace-lcov";
        cargoArtifacts = workspaceCov;

        FM_DISCOVER_API_VERSION_TIMEOUT = "10";

        buildPhaseCargoCommand = (
          ''
            source <(cargo llvm-cov show-env --export-prefix)
          ''
          + lib.concatStringsSep "\n" (
            lib.replicate times ''
              env RUST_BACKTRACE=1 RUST_LOG=info cargo nextest run --locked --workspace --all-targets --cargo-profile $CARGO_PROFILE --profile nix-ccov --test-threads=$(($(nproc) * 2))
            ''
          )
          + ''
            mkdir -p $out
            cargo llvm-cov report --profile $CARGO_PROFILE --lcov --output-path $out/lcov.info
          ''
        );
        installPhaseCommand = "true";
        nativeBuildInputs = [ pkgs.cargo-llvm-cov ];
        doCheck = false;
      };

    workspaceTestCov = workspaceTestCovBase { times = 1; };
    workspaceTest5TimesCov = workspaceTestCovBase { times = 5; };
    workspaceTest10TimesCov = workspaceTestCovBase { times = 10; };

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

    guardianBackupTest = craneLibTests.mkCargoDerivation {
      pname = "${commonCliTestArgs.pname}-guardian-backp";
      cargoArtifacts = workspaceBuild;
      buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/tests/guardian-backup.sh";
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

    ciTestAllBase =
      { times }:
      craneLibTests.mkCargoDerivation {
        pname = "${commonCliTestArgs.pname}-all";
        cargoArtifacts = craneMultiBuild.default.${craneLib.cargoProfile or "release"}.workspaceBuild;

        FM_DISCOVER_API_VERSION_TIMEOUT = "10";

        # One normal run, then if succeeded, modify the "always success test" to fail,
        # and make sure we detect it (happened too many times that we didn't).
        # Thanks to early termination, this should be all very quick, as we actually
        # won't start other tests.
        buildPhaseCargoCommand = ''
          # when running on a wasm32-unknown toolchain...
          if [ "$CARGO_BUILD_TARGET" == "wasm32-unknown-unknown" ]; then
            # import pre-built wasm32-unknown wasm test artifacts
            # notably, they are extracted to target's sub-directory, where wasm-test.sh expects them
            inheritCargoArtifacts ${
              craneMultiBuild.wasm32-unknown.${craneLib.cargoProfile or "release"}.workspaceBuildWasmTest
            } "target/pkgs/fedimint-wasm-tests"
          fi
          # default to building for native; running test for cross-compilation targets
          # here doesn't make any sense, and `wasm32-unknown-unknown` toolchain is used
          # mostly to opt-in into wasm tests
          unset CARGO_BUILD_TARGET

          patchShebangs ./scripts
          export CARGO_DENY_COMPILATION=1
          export FM_TEST_CI_ALL_TIMES=${builtins.toString times}
          export FM_TEST_CI_ALL_DISABLE_ETA=1
          ./scripts/tests/test-ci-all.sh || exit 1
          cp scripts/tests/always-success-test.sh scripts/tests/always-success-test.sh.bck
          sed -i -e 's/exit 0/exit 1/g' scripts/tests/always-success-test.sh
          echo "Verifying failure detection..."
          ./scripts/tests/test-ci-all.sh 1>/dev/null 2>/dev/null && exit 1
          cp -f scripts/tests/always-success-test.sh.bck scripts/tests/always-success-test.sh
        '';
      };

    ciTestAll = ciTestAllBase { times = 1; };
    ciTestAll5Times = ciTestAllBase { times = 5; };

    alwaysFailTest = craneLibTests.mkCargoDerivation {
      pname = "${commonCliTestArgs.pname}-always-fail";
      cargoArtifacts = workspaceBuild;
      buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/tests/always-fail-test.sh";
    };

    wasmTest = craneLibTests.mkCargoDerivation {
      pname = "wasm-test";
      # TODO: https://github.com/ipetkov/crane/issues/416
      cargoArtifacts = craneMultiBuild.default.${craneLib.cargoProfile or "release"}.workspaceBuild;
      nativeBuildInputs = commonCliTestArgs.nativeBuildInputs ++ [
        pkgs.firefox
        pkgs.wasm-bindgen-cli
        pkgs.geckodriver
        pkgs.wasm-pack
      ];
      buildPhaseCargoCommand = ''
        inheritCargoArtifacts ${
          craneMultiBuild.wasm32-unknown.${craneLib.cargoProfile or "release"}.workspaceBuildWasmTest
        } "target/pkgs/fedimint-wasm-tests"
        patchShebangs ./scripts; SKIP_CARGO_BUILD=1 ./scripts/tests/wasm-test.sh'';
    };

    fedimint-pkgs = fedimintBuildPackageGroup {
      pname = "fedimint-pkgs";

      packages = [
        "fedimintd"
        "fedimint-cli"
        "fedimint-dbtool"
        "fedimint-recoverytool"
      ];
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

      packages = [ "fedimint-client" ];
    };

    fedimint-client-wasm = fedimintBuildPackageGroup {
      pname = "fedimint-client-wasm";

      packages = [ "fedimint-client-wasm" ];
    };

    devimint = fedimintBuildPackageGroup {
      pname = "devimint";
      packages = [ "devimint" ];
    };

    fedimint-load-test-tool = fedimintBuildPackageGroup {
      pname = "fedimint-load-test-tool";
      packages = [ "fedimint-load-test-tool" ];
    };

    fedimintd = flakeboxLib.pickBinary {
      pkg = fedimint-pkgs;
      bin = "fedimintd";
    };

    fedimint-cli = flakeboxLib.pickBinary {
      pkg = fedimint-pkgs;
      bin = "fedimint-cli";
    };
    fedimint-dbtool = flakeboxLib.pickBinary {
      pkg = fedimint-pkgs;
      bin = "fedimint-dbtool";
    };
    gatewayd = flakeboxLib.pickBinary {
      pkg = gateway-pkgs;
      bin = "gatewayd";
    };
    gateway-cli = flakeboxLib.pickBinary {
      pkg = gateway-pkgs;
      bin = "gateway-cli";
    };

    gateway-cln-extension = flakeboxLib.pickBinary {
      pkg = gateway-pkgs;
      bin = "gateway-cln-extension";
    };

    fedimint-recoverytool = flakeboxLib.pickBinary {
      pkg = fedimint-pkgs;
      bin = "fedimint-recoverytool";
    };

    container =
      let
        entrypointScript = pkgs.writeShellScriptBin "entrypoint" ''
          exec bash "${../misc/fedimintd-container-entrypoint.sh}" "$@"
        '';
        defaultPackages = [
          pkgs.bash
          pkgs.coreutils
          pkgs.fakeNss
          pkgs.busybox
          pkgs.curl
          pkgs.rsync
        ];
      in
      {
        fedimintd = pkgs.dockerTools.buildLayeredImage {
          name = "fedimintd";
          contents = [ fedimint-pkgs ] ++ defaultPackages;
          config = {
            Cmd = [ ]; # entrypoint will handle empty vs non-empty cmd
            Env = [ "FM_DATA_DIR=/data" ];
            Entrypoint = [ "${entrypointScript}/bin/entrypoint" ];
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
          contents = [ fedimint-pkgs ] ++ defaultPackages;
          config = {
            Cmd = [ "${fedimint-pkgs}/bin/fedimint-cli" ];
          };
        };

        gatewayd = pkgs.dockerTools.buildLayeredImage {
          name = "gatewayd";
          contents = [ gateway-pkgs ] ++ defaultPackages;
          config = {
            Cmd = [ "${gateway-pkgs}/bin/gatewayd" ];
          };
        };

        cln-light-gateway =
          let
            entrypoint = pkgs.writeShellScriptBin "entrypoint.sh" ''
              ${pkgs.clightning}/bin/lightningd \
                --lightning-dir=/lightning \
                --disable-plugin=bcli \
                --network=$NETWORK \
                --plugin=${pkgs.trustedcoin}/bin/trustedcoin \
                --plugin=${gateway-pkgs}/bin/gateway-cln-extension \
                --fm-gateway-listen=0.0.0.0:3301 \
                $@
            '';
          in
          pkgs.dockerTools.buildLayeredImage {
            name = "cln-light-gateway";
            contents = [
              gateway-pkgs
              pkgs.clightning
              pkgs.trustedcoin
              pkgs.cacert
            ] ++ defaultPackages;
            config = {
              Cmd = [ "${entrypoint}/bin/entrypoint.sh" ];
              Volumes = {
                "/lightning" = { };
              };
              ExposedPorts = {
                "9735/tcp" = { };
                "3301/tcp" = { };
              };
              Env = [ "NETWORK=bitcoin" ];
            };
          };

        gateway-cli = pkgs.dockerTools.buildLayeredImage {
          name = "gateway-cli";
          contents = [ gateway-pkgs ] ++ defaultPackages;
          config = {
            Cmd = [ "${gateway-pkgs}/bin/gateway-cli" ];
          };
        };

        devtools = pkgs.dockerTools.buildLayeredImage {
          name = "fedimint-devtools";
          contents = [
            devimint
            fedimint-dbtool
            fedimint-load-test-tool
            fedimint-recoverytool
          ] ++ defaultPackages;
          config = {
            Cmd = [ "${pkgs.bash}/bin/bash" ];
          };
        };
      };
  }
)
