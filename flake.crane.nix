{ pkgs, lib, advisory-db, clightning-dev, pkgs-kitman, moreutils-ts }:
craneLib:
let
  # filter source code at path `src` to include only the list of `modules`
  filterModules = modules: raw-src:
    let
      src = builtins.path { path = raw-src; name = "fedimint"; };
      basePath = toString src + "/";
      relPathAllCargoTomlFiles = builtins.filter
        (pathStr: lib.strings.hasSuffix "/Cargo.toml" pathStr)
        (builtins.map (path: lib.removePrefix basePath (toString path)) (lib.filesystem.listFilesRecursive src));
    in
    lib.cleanSourceWith {
      filter = (path: type:
        let
          relPath = lib.removePrefix basePath (toString path);
          includePath =
            # traverse only into directories that somewhere in there contain `Cargo.toml` file, or were explicitly whitelisted
            (type == "directory" && lib.any (cargoTomlPath: lib.strings.hasPrefix relPath cargoTomlPath) relPathAllCargoTomlFiles) ||
            lib.any
              (re: builtins.match re relPath != null)
              ([ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".*/Cargo.toml" ".*/proto/.*" ] ++ builtins.concatLists (map (name: [ name "${name}/.*" ]) modules));
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
  filterWorkspaceDepsBuildFiles = src: filterSrcWithRegexes [ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".*/Cargo.toml" ".*/proto/.*" ] src;

  # Filter only files relevant to building the workspace
  filterWorkspaceFiles = src: filterSrcWithRegexes [ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".*/Cargo.toml" ".*\.rs" ".*\.html" ".*/proto/.*" "db/migrations/.*" ] src;

  # Like `filterWorkspaceFiles` but with `./scripts/` and `./misc/test/` included
  filterWorkspaceTestFiles = src: filterSrcWithRegexes [ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".*/Cargo.toml" ".*\.rs" ".*\.html" ".*/proto/.*" "scripts/.*" "misc/test/.*" ] src;

  filterSrcWithRegexes = regexes: raw-src:
    let
      src = builtins.path { path = raw-src; name = "fedimint"; };
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
in
rec {

  cargo-llvm-cov = craneLib.buildPackage rec {
    pname = "cargo-llvm-cov";
    version = "0.4.14";
    buildInputs = commonArgs.buildInputs;

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
  };
  commonArgsBase = {
    pname = "fedimint-workspace";

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
  } // commonEnvs;

  commonArgs = commonArgsBase // {
    src = filterWorkspaceFiles ./.;
  };

  commonArgsDepsOnly = commonArgsBase // {
    cargoVendorDir = craneLib.vendorCargoDeps {
      src = filterWorkspaceFiles ./.;
    };
    # copy over the linker/ar wrapper scripts which by default would get
    # stripped by crane
    dummySrc = craneLib.mkDummySrc {
      src = filterWorkspaceDepsBuildFiles ./.;
      extraDummyScript = ''
        cp -ar ${./.cargo} --no-target-directory $out/.cargo
      '';
    };
  };

  commonCliTestArgs = commonArgs // {
    pname = "fedimint-test";
    version = "0.0.1";
    src = filterWorkspaceTestFiles ./.;
    # there's no point saving the `./target/` dir
    doInstallCargoArtifacts = false;
    # the build command will be the test
    doCheck = true;
  };

  workspaceDeps = craneLib.buildDepsOnly (commonArgsDepsOnly // {
    version = "0.0.1";
    buildPhaseCargoCommand = "cargo doc --locked --profile $CARGO_PROFILE ; cargo check --locked --profile $CARGO_PROFILE --all-targets ; cargo build --locked --profile $CARGO_PROFILE --all-targets";
    doCheck = false;
  });

  workspaceBuild = craneLib.cargoBuild (commonArgs // {
    version = "0.0.1";
    cargoArtifacts = workspaceDeps;
    cargoExtraArgs = "--locked";
    doCheck = false;
  });

  workspaceTest = craneLib.cargoTest (commonArgs // {
    version = "0.0.1";
    cargoArtifacts = workspaceDeps;
  });

  workspaceTestDoc = craneLib.cargoTest (commonArgs // {
    version = "0.0.1";
    cargoTestExtraArgs = "--doc";
    cargoArtifacts = workspaceDeps;
  });

  workspaceClippy = craneLib.cargoClippy (commonArgs // {
    version = "0.0.1";
    cargoArtifacts = workspaceDeps;

    cargoClippyExtraArgs = "--all-targets --no-deps -- --deny warnings";
    doInstallCargoArtifacts = false;
  });

  workspaceDoc = craneLib.mkCargoDerivation (commonArgs // {
    version = "0.0.1";
    cargoArtifacts = workspaceDeps;
    preConfigure = ''
      export RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links'
    '';
    buildPhaseCargoCommand = "cargo doc --no-deps --document-private-items";
    doInstallCargoArtifacts = false;
    postInstall = ''
      cp -a target/doc/ $out
    '';
    doCheck = false;
  });

  # version of `workspaceDocs` with some nightly-only flags to publish
  workspaceDocExport = craneLib.mkCargoDerivation (commonArgs // {
    version = "0.0.1";
    # no need for inheriting any artifacts, as we are using it as a one-off, and only care
    # about the docs
    cargoArtifacts = null;
    preConfigure = ''
      export RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links -Z unstable-options --enable-index-page'
    '';
    buildPhaseCargoCommand = "cargo doc --no-deps --document-private-items";
    doInstallCargoArtifacts = false;
    installPhase = ''
      cp -a target/doc/ $out
    '';
    doCheck = false;
  });

  workspaceCargoUdeps = craneLib.mkCargoDerivation (commonArgs // {
    version = "0.0.1";
    # no need for inheriting any artifacts, as we are using it as a one-off, and only care
    # about the docs
    cargoArtifacts = null;
    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.cargo-udeps ];
    buildPhaseCargoCommand = "cargo udeps --all-targets --workspace";
    doInstallCargoArtifacts = false;
    doCheck = false;
  });

  workspaceAudit = craneLib.cargoAudit (commonArgs // {
    version = "0.0.1";
    pname = commonArgs.pname + "-audit";
    inherit advisory-db;
  });

  # Build only deps, but with llvm-cov so `workspaceCov` can reuse them cached
  workspaceDepsCov = craneLib.buildDepsOnly (commonArgsDepsOnly // {
    pnameSuffix = "-lcov-deps";
    version = "0.0.1";
    buildPhaseCargoCommand = "cargo llvm-cov --locked --workspace --profile $CARGO_PROFILE --no-report";
    cargoBuildCommand = "dontuse";
    cargoCheckCommand = "dontuse";
    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ cargo-llvm-cov ];
    doCheck = false;
  });

  workspaceCov = craneLib.buildPackage (commonArgs // {
    pnameSuffix = "-lcov";
    version = "0.0.1";
    cargoArtifacts = workspaceDepsCov;
    buildPhaseCargoCommand = "mkdir -p $out ; env RUST_LOG=info,timing=debug cargo llvm-cov --locked --workspace --profile $CARGO_PROFILE --lcov --all-targets --tests --output-path $out/lcov.info --  --test-threads=$(($(nproc) * 2))";
    installPhaseCommand = "true";
    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ cargo-llvm-cov ];
    doCheck = false;
  });

  cliTestReconnect = craneLib.mkCargoDerivation (commonCliTestArgs // {
    pname = "${commonCliTestArgs.pname}-reconnect";
    version = "0.0.1";
    cargoArtifacts = workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/reconnect-test.sh";
  });

  cliTestUpgrade = craneLib.mkCargoDerivation (commonCliTestArgs // {
    pname = "${commonCliTestArgs.pname}-upgrade";
    version = "0.0.1";
    cargoArtifacts = workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/upgrade-test.sh";
  });

  cliTestLatency = craneLib.mkCargoDerivation (commonCliTestArgs // {
    pname = "${commonCliTestArgs.pname}-latency";
    version = "0.0.1";
    cargoArtifacts = workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/latency-test.sh";
  });

  cliTestCli = craneLib.mkCargoDerivation (commonCliTestArgs // {
    pname = "${commonCliTestArgs.pname}-cli";
    version = "0.0.1";
    cargoArtifacts = workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/cli-test.sh";
  });

  cliRustTests = craneLib.mkCargoDerivation (commonCliTestArgs // {
    pname = "${commonCliTestArgs.pname}-rust-tests";
    version = "0.0.1";
    cargoArtifacts = workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/rust-tests.sh";
  });

  cliTestsAll = craneLib.mkCargoDerivation (commonCliTestArgs // {
    pname = "${commonCliTestArgs.pname}-all";
    version = "0.0.1";
    cargoArtifacts = workspaceBuild;
    # One normal run, then if succeeded, modify the "always success test" to fail,
    # and make sure we detect it (happened too many times that we didn't).
    # Thanks to early termination, this should be all very quick, as we actually
    # won't start other tests.
    buildPhaseCargoCommand = ''
      patchShebangs ./scripts
      ./scripts/test-ci-all.sh || exit 1
      sed -i -e 's/exit 0/exit 1/g' scripts/always-success-test.sh
      echo "Verifying failure detection..."
      ./scripts/test-ci-all.sh 1>/dev/null 2>/dev/null && exit 1
    '';
  });

  cliTestAlwaysFail = craneLib.mkCargoDerivation (commonCliTestArgs // {
    pname = "${commonCliTestArgs.pname}-always-fail";
    version = "0.0.1";
    cargoArtifacts = workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/always-fail-test.sh";
  });


  # Compile a group of packages together
  #
  # This unifies their cargo features and avoids building common dependencies multiple
  # times, but will produce a derivation with all listed packages.
  pkgsBuild = { name, pkgs, dirs, defaultBin ? null }:
    let
      # "--package x --package y" args passed to cargo
      pkgsArgs = lib.strings.concatStringsSep " " (lib.mapAttrsToList (name: value: "--package ${name}") pkgs);
      deps = craneLib.buildDepsOnly (commonArgsDepsOnly // {
        pname = name;
        version = "0.0.1";
        buildPhaseCargoCommand = "cargo build --profile $CARGO_PROFILE ${pkgsArgs}";
        doCheck = false;
      });

    in

    craneLib.buildPackage (commonArgs // {
      meta = { mainProgram = defaultBin; };
      pname = "${name}";
      version = "0.0.1";
      cargoArtifacts = deps;

      src = filterModules dirs ./.;
      cargoExtraArgs = pkgsArgs;

      # if needed we will check the whole workspace at once with `workspaceBuild`
      doCheck = false;
    });


  # Cross-compile a group of packages together.
  #
  # This unifies their cargo features and avoids building common dependencies multiple
  # times, but will produce a derivation with all listed packages.
  pkgsCrossBuild = { name, pkgs, dirs, target }:
    if target == null then
      pkgsBuild { inherit name pkgs dirs; }
    else
      let
        # "--package x --package y" args passed to cargo
        pkgsArgs = lib.strings.concatStringsSep " " (lib.mapAttrsToList (name: value: "--package ${name}") pkgs);
        deps = craneLib.buildDepsOnly (commonArgsDepsOnly // {
          pname = "${name}-${target.name}";
          version = "0.0.1";
          # workaround: on wasm, we can't compile all deps, so narrow dependency build
          # to ones used by the client package only
          buildPhaseCargoCommand = "cargo build --profile $CARGO_PROFILE --target ${target.name} ${pkgsArgs}";
          doCheck = false;

          preBuild = ''
            patchShebangs .cargo/
          '' + target.extraEnvs;
        });

      in
      craneLib.buildPackage (commonArgs // {
        pname = "${name}-${target.name}";
        version = "0.0.1";
        cargoArtifacts = deps;

        src = filterModules dirs ./.;
        cargoExtraArgs = "--target ${target.name} ${pkgsArgs}";

        # if needed we will check the whole workspace at once with `workspaceBuild`
        doCheck = false;
        preBuild = ''
          patchShebangs .cargo/
        '' + target.extraEnvs;
      });

  fedimint-pkgs = pkgsBuild {
    name = "fedimint-pkgs";

    pkgs = {
      fedimintd = { };
      fedimint-cli = { };
      fedimint-tests = { };
    };

    defaultBin = "fedimintd";
    dirs = [
      "crypto/aead"
      "crypto/derive-secret"
      "crypto/hkdf"
      "crypto/tbs"
      "fedimintd"
      "fedimint-bin-tests"
      "fedimint-bitcoind"
      "fedimint-build"
      "fedimint-cli"
      "fedimint-client"
      "fedimint-client-legacy"
      "fedimint-core"
      "fedimint-derive"
      "fedimint-dbtool"
      "fedimint-rocksdb"
      "fedimint-server"
      "fedimint-logging"
      "gateway/ln-gateway"
      "modules"
    ];
  };

  gateway-pkgs = pkgsBuild {
    name = "gateway-pkgs";

    pkgs = {
      ln-gateway = { };
      gateway-cli = { };
    };

    dirs = [
      "crypto/aead"
      "crypto/derive-secret"
      "crypto/tbs"
      "crypto/hkdf"
      "modules/fedimint-ln"
      "fedimint-bin-tests"
      "fedimint-bitcoind"
      "fedimint-client"
      "fedimint-client-legacy"
      "fedimint-core"
      "fedimint-derive"
      "fedimint-dbtool"
      "fedimint-rocksdb"
      "fedimint-build"
      "fedimint-logging"
      "gateway/ln-gateway"
      "gateway/cli"
      "modules"
    ];
  };

  client-pkgs = { target ? null }: pkgsCrossBuild {
    name = "client-pkgs";
    inherit target;

    pkgs = {
      fedimint-client-legacy = { };
    } // lib.optionalAttrs (target == null || target.name != "wasm32-unknown-unknown") {
      # broken on wasm32
      fedimint-sqlite = { };
    };
    dirs = [
      "crypto/aead"
      "crypto/derive-secret"
      "crypto/tbs"
      "crypto/hkdf"
      "fedimint-bin-tests"
      "fedimint-bitcoind"
      "fedimint-client"
      "fedimint-client-legacy"
      "fedimint-core"
      "fedimint-derive"
      "fedimint-dbtool"
      "fedimint-rocksdb"
      "fedimint-sqlite"
      "fedimint-logging"
      "modules"
    ];
  };
}

