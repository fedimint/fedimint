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

  pickBinary =
    {
      pkg,
      name ? null,
      bin ? null,
      bins ? [ ],
    }:
    pkgs.stdenv.mkDerivation {
      system = pkgs.system;
      pname = if name != null then name else bin;
      version = pkg.version;

      dontUnpack = true;
      # just don't mess with it
      dontStrip = true;

      installPhase = ''
        mkdir -p $out/bin
        ${if bin != null then "cp -a ${pkg}/bin/${bin} $out/bin/${bin}" else ""}
        ${builtins.concatStringsSep "\n" (map (b: "cp -a ${pkg}/bin/${b} $out/bin/${b}") bins)}
      '';
    };

  # `moreutils/bin/parallel` and `parallel/bin/parallel` conflict, so just use
  # the binary we need from `moreutils`
  moreutils-ts = pkgs.writeShellScriptBin "ts" ''exec ${pkgs.moreutils}/bin/ts "$@"'';

  # placeholder we use to avoid actually needing to detect hash via running `git`
  # 012345... for easy recognizability (in case something went wrong),
  # rest randomized to avoid accidentally overwriting innocent bytes in the binary
  gitHashPlaceholderValue = "01234569abcdef7afa1d2683a099c7af48a523c1";

  filterWorkspaceDepsBuildFilesRegex = [
    "Cargo\\.lock"
    "Cargo\\.toml"
    ".cargo"
    ".cargo/.*"
    ".config"
    ".config/.*"
    ".*/Cargo\\.toml"
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
      filter =
        path: type:
        let
          relPath = lib.removePrefix basePath (toString path);
          includePath = (type == "directory") || lib.any (re: builtins.match re relPath != null) regexes;
        in
        # uncomment to debug:
        # builtins.trace "${relPath}: ${lib.boolToString includePath}"
        includePath;
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
        ".*\\.rs"
        ".*\\.html"
        ".*/proto/.*"
        ".*/clippy\\.toml"
        "db/migrations/.*"
        "devimint/src/cfg/.*"
        "fedimint-server/src/test_fixtures/.*"
        "docs/.*\\.md"
        "fedimint-ui-common/assets/.*"
      ]
    ) src;

  # Like `filterWorkspaceFiles` but with `./scripts/` included
  filterWorkspaceTestFiles =
    src:
    filterSrcWithRegexes (
      filterWorkspaceDepsBuildFilesRegex
      ++ [
        ".*\\.rs"
        ".*\\.html"
        ".*/proto/.*"
        "db/migrations/.*"
        "devimint/src/cfg/.*"
        "fedimint-server/src/test_fixtures/.*"
        "scripts/.*"
        "docs/.*\\.md"
        "fedimint-ui-common/assets/.*"
      ]
    ) src;

  filterWorkspaceAuditFiles =
    src: filterSrcWithRegexes (filterWorkspaceDepsBuildFilesRegex ++ [ "deny.toml" ]) src;

  # env vars for linking rocksdb
  commonEnvsCross =
    let
      build_arch_underscores =
        lib.strings.replaceStrings [ "-" ] [ "_" ]
          pkgs.stdenv.buildPlatform.config;
      sqlcipherStatic = pkgs.pkgsStatic.sqlcipher.overrideAttrs (old: {
        configureFlags = old.configureFlags ++ [
          "--disable-shared"
          "--enable-static"
        ];
        buildFlags = [ "lib" ];
        installTargets = [
          "install-lib"
          "install-headers"
          "install-pc"
        ];
        postInstall = ''
          mkdir $out/include/sqlcipher
          mv $out/include/sqlite3.h $out/include/sqlcipher/sqlite3.h
          mv $out/include/sqlite3ext.h $out/include/sqlcipher/sqlite3ext.h
          mv $out/lib/lib{sqlite3,sqlcipher}.a
          mv $out/lib/pkgconfig/{sqlite3,sqlcipher}.pc
          substituteInPlace $out/lib/pkgconfig/sqlcipher.pc \
            --replace-fail "-lsqlite3" "-lsqlcipher" \
            --replace-fail "-lz" "-lz -lcrypto" \
            --replace-fail "includedir}" "includedir}/sqlcipher"
        '';
      });
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
      "ROCKSDB_${build_arch_underscores}_LIB_DIR" = "${
        pkgs.rocksdb_8_11.override { enableLiburing = false; }
      }/lib/";

      # does not produce static lib in most versions
      "SNAPPY_${build_arch_underscores}_STATIC" = "true";
      "SNAPPY_${build_arch_underscores}_LIB_DIR" = "${pkgs.pkgsStatic.snappy}/lib/";
      # "SNAPPY_${build_arch_underscores}_COMPILE" = "true";

      "SQLITE3_${build_arch_underscores}_STATIC" = "true";
      "SQLITE3_${build_arch_underscores}_LIB_DIR" = "${pkgs.pkgsStatic.sqlite.out}/lib/";

      "SQLCIPHER_${build_arch_underscores}_LIB_DIR" = "${sqlcipherStatic}/lib/";
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
    JEMALLOC_SYS_WITH_LG_PAGE = 16;
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
      ];

    CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS = "--cfg getrandom_backend=\"wasm_js\"";

    nativeBuildInputs =
      with pkgs;
      [
        zlib

        pkg-config
        moreutils-ts
        cmake
        rust-bindgen

        # tests
        (lib.hiPrio pkgs.bashInteractive)
        bc
        bitcoind
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

        removeReferencesTo
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
      ];

    # we carefully optimize our debug symbols on cargo level,
    # and in case of errors and panics, would like to see the
    # line numbers etc.
    dontStrip = true;

    postFixup = ''
      # the toolchain package itself is handled by crane, so it's easiest
      # to just recover its path from the current rustc binary itself
      rust_toolchain_pkg=$(dirname $(dirname $(which rustc)))
      >&2 echo "Removing references to $rust_toolchain_pkg"

      find "$out" -type f -executable -exec remove-references-to -t $rust_toolchain_pkg '{}' +
    '';
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
        commonEnvsBuild
        // commonArgs
        // {
          src = filterWorkspaceBuildFiles commonSrc;
        }
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

    devimintStaticDataDir = pkgs.stdenv.mkDerivation {
      name = "devimint-static-data-dir";
      src = pkgs.emptyDirectory;

      installPhase = ''
        mkdir -p $out/share/
        cp -r ${../devimint/share}/* $out/share/devimint/
      '';
    };

    # copied and modified from flakebox, to add `runLowPrio`, due to mistake in flakebox
    # and also, it wraps the `devimint` into a shell scrip that points at the the static
    rawBuildPackageGroup =
      {
        pname ? null,
        packages,
        mainProgram ? null,
        features ? [ ],
        ...
      }@origArgs:
      let
        args = builtins.removeAttrs origArgs [
          "mainProgram"
          "pname"
          "packages"
          "features"
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
        # "--features pkg/feat --features pkg/feat" args passed to cargo
        featuresArgs = lib.strings.concatStringsSep " " (builtins.map (f: "--features ${f}") features);
        extraArgs = lib.strings.concatStringsSep " " (
          builtins.filter (s: s != "") [
            pkgsArgs
            featuresArgs
          ]
        );

        deps = craneLib.buildDepsOnly (
          args
          // (lib.optionalAttrs (pname != null) { inherit pname; })
          // {
            buildPhaseCargoCommand = "runLowPrio cargo build --profile $CARGO_PROFILE ${extraArgs}";
          }
        );
      in
      craneLib.buildPackage (
        args
        // (lib.optionalAttrs (pname != null) { inherit pname; })
        // {
          cargoArtifacts = deps;
          meta = lib.optionalAttrs (mainProgram != null) { inherit mainProgram; };
          cargoBuildCommand = "runLowPrio bash ${./bin/cargo-with-memlimit.sh} build --profile $CARGO_PROFILE";
          cargoExtraArgs = "${extraArgs}";

          # If the build contains `devimint`, wrap it in a script that will set
          # a correct `FM_DEVIMINT_STATIC_DATA_DIR`.
          postInstall = ''
            if [ -f $out/bin/devimint ]; then
              mv $out/bin/devimint $out/bin/devimint.orig
              cat > $out/bin/devimint << 'EOF'
            #!${pkgs.bash}/bin/bash
            SCRIPT_PATH="$(${pkgs.coreutils}/bin/readlink -f "$0")"
            SCRIPT_DIR="$(${pkgs.coreutils}/bin/dirname "$SCRIPT_PATH")"

            export FM_DEVIMINT_STATIC_DATA_DIR
            FM_DEVIMINT_STATIC_DATA_DIR=''${FM_DEVIMINT_STATIC_DATA_DIR:-${devimintStaticDataDir}/share/devimint}
            exec -a devimint "$SCRIPT_DIR/devimint.orig" "$@"
            EOF
              chmod +x $out/bin/devimint
            fi
          '';

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
    inherit devimintStaticDataDir;
    commonArgsBase = commonArgs;

    workspaceDeps = craneLib.buildWorkspaceDepsOnly {
      buildPhaseCargoCommand = "runLowPrio cargo check --profile $CARGO_PROFILE --all-targets --locked ; runLowPrio cargo doc --profile $CARGO_PROFILE --locked --no-deps; runLowPrio cargo build --profile $CARGO_PROFILE --locked --all-targets";
    };

    # like `workspaceDeps` but don't run `cargo doc`
    workspaceDepsNoDocs = craneLib.buildWorkspaceDepsOnly {
      buildPhaseCargoCommand = "runLowPrio cargo check --profile $CARGO_PROFILE --all-targets --locked ; runLowPrio cargo build --profile $CARGO_PROFILE --locked --all-targets";
    };

    workspaceBuild = craneLib.buildWorkspace {
      cargoArtifacts = workspaceDeps;
      buildPhaseCargoCommand = "runLowPrio cargo check --profile $CARGO_PROFILE --all-targets --locked ; runLowPrio cargo doc --profile $CARGO_PROFILE --locked --no-deps; runLowPrio cargo build --profile $CARGO_PROFILE --locked --all-targets";
    };

    workspaceAllBins = craneLib.buildPackage {
      cargoArtifacts = workspaceBuild;
      buildPhaseCargoCommand = ''
        cargoBuildLog=$(mktemp cargoBuildLogXXXX.json)
        runLowPrio cargo build --profile $CARGO_PROFILE --locked --all-targets --message-format json-render-diagnostics >"$cargoBuildLog"
      '';
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

    cargoWorkspacesCommand =
      { cmd, pnameSuffix }:
      let
        pname = "${commonArgs.pname}-cargo-workspaces-cmd-${pnameSuffix}";
        nativeBuildInputs = commonArgs.nativeBuildInputs ++ [
          pkgs.cargo-workspaces
        ];
        buildPhaseCargoCommand = "cargo workspaces exec ${cmd}";
        deps = craneLib.buildDepsOnly {
          inherit pname nativeBuildInputs buildPhaseCargoCommand;
          doCheck = false;
        };
      in
      craneLib.mkCargoDerivation {
        inherit pname nativeBuildInputs buildPhaseCargoCommand;
        cargoArtifacts = deps;
        doInstallCargoArtifacts = false;
        doCheck = false;
      };

    cargoCheckCommand =
      { args }:
      let
        fullCmd = "cargo check ${args}";
        deps = craneLib.buildDepsOnly {
          pname = "${commonArgs.pname}-cargo-check-features-deps";
          nativeBuildInputs = commonArgs.nativeBuildInputs;
          buildPhaseCargoCommand = fullCmd;
          doCheck = false;
        };
      in
      craneLib.mkCargoDerivation {
        pname = "${commonArgs.pname}-cargo-workspaces-cmd";
        cargoArtifacts = deps;
        nativeBuildInputs = commonArgs.nativeBuildInputs;
        buildPhaseCargoCommand = fullCmd;
        doInstallCargoArtifacts = false;
        doCheck = false;
      };

    cargoAudit = craneLib.cargoAudit {
      inherit advisory-db;
      src = filterWorkspaceAuditFiles commonSrc;
    };

    cargoDeny = craneLib.cargoDeny {
      src = filterWorkspaceAuditFiles commonSrc;
      cargoDenyChecks = "--hide-inclusion-graph bans licenses sources";
    };

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
      craneLib.mkCargoDerivation {
        pname = "fedimint-workspace-lcov-test";
        cargoArtifacts = workspaceCov;

        FM_DISCOVER_API_VERSION_TIMEOUT = "10";

        buildPhaseCargoCommand = ''
          source <(cargo llvm-cov show-env --export-prefix)
        ''
        + lib.concatStringsSep "\n" (
          lib.replicate times ''
            env RUST_BACKTRACE=1 RUST_LIB_BACKTRACE=0 RUST_LOG=info cargo nextest run --locked --workspace --all-targets --cargo-profile $CARGO_PROFILE --profile nix-ccov --test-threads=$(($(nproc) * 2))
          ''
        )
        + ''
          mkdir -p $out
          cargo llvm-cov report --profile $CARGO_PROFILE --lcov --output-path $out/lcov.info
        '';
        doInstallCargoArtifacts = false;
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
      {
        times,
        useIroh ? false,
      }:
      (craneLibTests.mkCargoDerivation {
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

          if [ "$CARGO_PROFILE" = "ci" ]; then
            export CI=true
          fi
          if [ "${builtins.toString useIroh}" == "1" ]; then
            >&2 echo "Iroh enabled"
            export FM_ENABLE_IROH=true
          fi
          ./scripts/tests/test-ci-all.sh || exit 1
          cp scripts/tests/always-success-test.sh scripts/tests/always-success-test.sh.bck
          sed -i -e 's/exit 0/exit 1/g' scripts/tests/always-success-test.sh
          echo "Verifying failure detection..."
          ./scripts/tests/test-ci-all.sh 1>/dev/null 2>/dev/null && exit 1
          cp -f scripts/tests/always-success-test.sh.bck scripts/tests/always-success-test.sh
        '';
      }).overrideAttrs
        (
          final: prev: {
            # flakebox will append wasm toolchain to the pname, which
            # looks meh in the logs
            pname = "test-ci-all";
          }
        );

    ciTestAll = ciTestAllBase { times = 1; };
    ciTestAllWithIroh = ciTestAllBase {
      times = 1;
      useIroh = true;
    };
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

    wasmBundleClientPkgDeps = craneLib.buildWorkspaceDepsOnly {
      pname = "${commonArgs.pname}-client-wasm";
      "CARGO_PROFILE_RELEASE_OPT_LEVEL" = "z";
      buildPhaseCargoCommand = "runLowPrio cargo build --profile $CARGO_PROFILE --locked -p fedimint-client-wasm";
    };

    wasmBundleClientPkg = craneLib.buildWorkspace {
      cargoArtifacts = wasmBundleClientPkgDeps;
      pname = "${commonArgs.pname}-client-wasm";
      "CARGO_PROFILE_RELEASE_OPT_LEVEL" = "z";
      buildPhaseCargoCommand = "runLowPrio cargo build --profile $CARGO_PROFILE --locked -p fedimint-client-wasm";
    };

    wasmBundle = craneLibTests.mkCargoDerivation {
      pname = "wasm-bundle";
      cargoArtifacts = wasmBundleClientPkg;
      "CARGO_PROFILE_RELEASE_OPT_LEVEL" = "z";
      nativeBuildInputs = commonCliTestArgs.nativeBuildInputs ++ [
        pkgs.wasm-bindgen-cli
        pkgs.wasm-pack
        pkgs.binaryen
      ];
      buildPhaseCargoCommand = ''
        runLowPrio wasm-pack build --release fedimint-client-wasm
        runLowPrio wasm-pack build --release --target web --out-dir web fedimint-client-wasm
        mkdir -p $out/share/fedimint-client-wasm
        mkdir -p $out/share/fedimint-client-wasm-web
        cp fedimint-client-wasm/pkg/* $out/share/fedimint-client-wasm
        cp fedimint-client-wasm/web/* $out/share/fedimint-client-wasm-web
      '';
    };

    fedimint-pkgs = fedimintBuildPackageGroup {
      pname = "fedimint-pkgs";

      packages = [
        "fedimintd"
        "fedimint-cli"
        "fedimint-dbtool"
        "fedimint-recoverytool"
      ];

      # Cargo features can't be enabled by default conditionally on the target
      # architecture, so we enable jemalloc here for the systems where it works.
      features = lib.optionals (pkgs.stdenv.isLinux || pkgs.stdenv.isDarwin) [
        "fedimintd/jemalloc"
        "fedimint-cli/jemalloc"
      ];
    };

    gateway-pkgs = fedimintBuildPackageGroup {
      pname = "gateway-pkgs";

      packages = [
        "fedimint-gateway-server"
        "fedimint-gateway-client"
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

    devimint-pkgs = fedimintBuildPackageGroup {
      pname = "devimint";
      packages = [ "devimint" ];
    };

    devimint = pickBinary {
      pkg = devimint-pkgs;
      name = "devimint";
      bins = [
        "devimint"
        "devimint.orig"
      ];
    };

    fedimint-load-test-tool = fedimintBuildPackageGroup {
      pname = "fedimint-load-test-tool";
      packages = [ "fedimint-load-test-tool" ];
    };

    fedimintd = pickBinary {
      pkg = fedimint-pkgs;
      bin = "fedimintd";
    };

    fedimint-cli = pickBinary {
      pkg = fedimint-pkgs;
      bin = "fedimint-cli";
    };
    fedimint-dbtool = pickBinary {
      pkg = fedimint-pkgs;
      bin = "fedimint-dbtool";
    };
    gatewayd = pickBinary {
      pkg = gateway-pkgs;
      bin = "gatewayd";
    };
    gateway-cli = pickBinary {
      pkg = gateway-pkgs;
      bin = "gateway-cli";
    };

    fedimint-recoverytool = pickBinary {
      pkg = fedimint-pkgs;
      bin = "fedimint-recoverytool";
    };

    fedimint-recurringd-pkgs = fedimintBuildPackageGroup {
      pname = "fedimint-recurringd-pkgs";
      packages = [ "fedimint-recurringd" ];
    };

    fedimint-recurringd = pickBinary {
      pkg = fedimint-recurringd-pkgs;
      bin = "fedimint-recurringd";
    };

    fedimint-recurringdv2-pkgs = fedimintBuildPackageGroup {
      pname = "fedimint-recurringdv2-pkgs";
      packages = [ "fedimint-recurringdv2" ];
    };

    fedimint-recurringdv2 = pickBinary {
      pkg = fedimint-recurringdv2-pkgs;
      bin = "fedimint-recurringdv2";
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

        gateway-cli = pkgs.dockerTools.buildLayeredImage {
          name = "gateway-cli";
          contents = [ gateway-pkgs ] ++ defaultPackages;
          config = {
            Cmd = [ "${gateway-pkgs}/bin/gateway-cli" ];
          };
        };

        fedimint-recurringd = pkgs.dockerTools.buildLayeredImage {
          name = "fedimint-recurringd";
          contents = [ fedimint-recurringd-pkgs ] ++ defaultPackages;
          config = {
            Cmd = [ "${fedimint-recurringd-pkgs}/bin/fedimint-recurringd" ];
          };
        };

        fedimint-recurringdv2 = pkgs.dockerTools.buildLayeredImage {
          name = "fedimint-recurringdv2";
          contents = [ fedimint-recurringdv2-pkgs ] ++ defaultPackages;
          config = {
            Cmd = [ "${fedimint-recurringdv2-pkgs}/bin/fedimint-recurringdv2" ];
          };
        };

        devtools = pkgs.dockerTools.buildLayeredImage {
          name = "fedimint-devtools";
          contents = [
            devimint
            fedimint-dbtool
            fedimint-load-test-tool
            fedimint-recoverytool
          ]
          ++ defaultPackages;
          config = {
            Cmd = [ "${pkgs.bash}/bin/bash" ];
          };
        };
      };

    cargoCheckWasmNoDefaultFeatures = cargoCheckCommand {
      args = "--package fedimint-client --package fedimint-client-wasm --package fedimint-wasm-tests --package fedimint-mintv2-client --package fedimint-walletv2-client --no-default-features";
    };

    cargoWorkspacesCheckDefaultFeatures = cargoWorkspacesCommand {
      cmd = "cargo check";
      pnameSuffix = "default-feats";
    };

    cargoWorkspacesCheckNoDefaultFeatures = cargoWorkspacesCommand {
      cmd = "cargo check --no-default-features";
      pnameSuffix = "no-default-feats";

    };
    cargoWorkspacesCheckAllFeatures = cargoWorkspacesCommand {
      cmd = "cargo check --all-features";
      pnameSuffix = "all-feats";
    };

    # Quick honggfuzz-based fuzzing of `fedimint-fuzz` bins.
    #
    # Non-obvious requirements (all load-bearing — changing any of these
    # tends to break the build in confusing ways):
    #
    # - `CARGO_TARGET_DIR=$PWD/target`. honggfuzz-rs ≥0.5.60's build.rs does
    #   `fs::copy(out_dir/honggfuzz, $CRATE_ROOT/$CARGO_HONGGFUZZ_TARGET_DIR/honggfuzz)`
    #   and cargo-hfuzz sets `CARGO_HONGGFUZZ_TARGET_DIR` from the env var
    #   `CARGO_TARGET_DIR` (defaulting to `hfuzz_target`). Cargo's
    #   `--target-dir` CLI flag is *not* picked up by cargo-hfuzz. Without
    #   this export the copy target dir doesn't exist and build.rs panics
    #   with an opaque ENOENT at line 134.
    #
    # - `-fuse-ld=mold`. iroh-relay declares `crate-type = ["lib", "cdylib"]`,
    #   so cargo links a `.so` for it. Honggfuzz's sancov `RUSTFLAGS` cause
    #   rustc to emit generic `std`/`alloc` instantiations (`Vec::reserve`,
    #   `Write::write_all`, …) as hidden symbols in dep rlibs, and bfd ld
    #   refuses to resolve those when linking the cdylib. mold accepts them.
    #   `-C link-dead-code` does *not* help — it just shifts the failure to
    #   different hidden symbols.
    #
    # - `cp noop.rs` + `--bin noop` in the deps phase. crane's
    #   `buildDepsOnly` replaces `src/bin/*.rs` with `fn main() {}` dummies.
    #   Cargo then doesn't pass `-lhfuzz` to a dummy that doesn't use the
    #   honggfuzz crate, so the sancov runtime is unresolved. The real
    #   `fuzz/src/bin/noop.rs` uses `honggfuzz::fuzz!` and we copy it back
    #   over the dummy to get one bin whose link edge keeps `-lhfuzz` alive;
    #   `--bin noop` restricts the deps build to it so we don't also hit
    #   the same issue on the other stubs.
    #
    # - Both phases pass `--package=fedimint-fuzz`. Without it, cargo
    #   resolves the build unit differently and invalidates the entire
    #   external-dep fingerprint cache between the two phases (434 vs 14
    #   recompilations on a warm cache, measured). This is why we build
    #   explicitly in the run phase and drive honggfuzz by hand instead of
    #   using `cargo hfuzz run`, which internally invokes `cargo build
    #   --bin <target>` without `--package`.
    #
    # - `env -u RUSTC_WRAPPER CC=clang`. honggfuzz's C build wants clang
    #   (sancov pass); the workspace's default `RUSTC_WRAPPER` (sccache-ish)
    #   caches artifacts keyed by the ambient RUSTFLAGS, which collides
    #   with the sancov flags cargo-hfuzz injects on top.
    quickFuzz =
      let
        pname = "${commonArgs.pname}-cargo-hfuzz";
        nativeBuildInputs = commonArgs.nativeBuildInputs ++ [
          pkgs.cargo-honggfuzz
          pkgs.lldb
          pkgs.clang
        ];
        buildInputs = commonArgs.buildInputs ++ [
          pkgs.libbfd_2_38
          pkgs.libunwind.dev
          pkgs.libopcodes_2_38
          pkgs.pkgsStatic.libblocksruntime
        ];
        # RUSTFLAGS shared by deps + run phases. `--cfg tokio_unstable` matches
        # the rest of the workspace; the mold link-arg is explained above.
        hfuzzRustflags = "--cfg tokio_unstable -C link-arg=-fuse-ld=${pkgs.mold}/bin/mold";
        deps = craneLib.buildDepsOnly {
          inherit pname nativeBuildInputs buildInputs;
          buildPhaseCargoCommand = ''
            export CARGO_TARGET_DIR=$PWD/target
            cp ${../fuzz/src/bin/noop.rs} ./fuzz/src/bin/noop.rs
            env -u RUSTC_WRAPPER CC=clang RUSTFLAGS="${hfuzzRustflags}" \
              cargo hfuzz build --package=fedimint-fuzz --bin noop
          '';
          doCheck = false;
        };
      in
      craneLib.mkCargoDerivation {
        inherit pname nativeBuildInputs buildInputs;
        cargoArtifacts = deps;
        buildPhaseCargoCommand = ''
          set -euo pipefail

          export CARGO_TARGET_DIR=$PWD/target
          # Build all fuzz bins in one cargo invocation with an explicit
          # `--package`. Without `--package`, cargo resolves the build unit
          # differently and invalidates the entire external-dep fingerprint
          # cache (434 vs 14 recompilations on a warm deps cache) — which
          # is exactly what `cargo hfuzz run <target>` does internally. So
          # we build explicitly here and drive honggfuzz by hand below.
          env -u RUSTC_WRAPPER CC=clang RUSTFLAGS="${hfuzzRustflags}" \
            cargo hfuzz build --package=fedimint-fuzz
          # Per-target honggfuzz budget; tune via HFUZZ_RUN_ARGS from the
          # caller (the previous `{{ARGS}}` here was an unused template
          # placeholder — honggfuzz parsed it as a bogus flag and aborted).
          runArgs="''${HFUZZ_RUN_ARGS:---run_time 5 -N 1000}"
          # noop is the deps-cache stub from fuzz/src/bin/noop.rs; nothing to fuzz there.
          for target in $(ls fuzz/src/bin/ | sed -e 's/\.rs$//' | grep -v '^noop$') ; do
            >&2 echo "Fuzzing ''${target}"
            mkdir -p "hfuzz_workspace/''${target}/input"
            target/honggfuzz \
              -W "hfuzz_workspace/''${target}" \
              -f "hfuzz_workspace/''${target}/input" \
              -P \
              $runArgs \
              -- "target/x86_64-unknown-linux-gnu/release/''${target}"
          done
        '';
        doInstallCargoArtifacts = false;
        doCheck = false;
      };

    vmTestFedimintd = lib.optionalAttrs pkgs.stdenv.isLinux (
      import ./tests/fedimintd.nix {
        inherit pkgs;
        fedimintdModule = import ./modules/fedimintd.nix;
        # this is so that we can reuse binaries from buildWorkspace step, which we typically do in the CI
        fedimintdPackage = workspaceAllBins;
      }
    );
  }
)
