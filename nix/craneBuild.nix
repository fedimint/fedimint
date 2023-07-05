# Build targets/outputs/packages that can be built using Nix in our project

{ pkgs, lib, advisory-db, ... }:
craneLib:
craneLib.overrideScope' (self: prev: {

  workspaceDeps = self.buildDepsOnly (prev.commonArgsDepsOnly // {
    version = "0.0.1";
    buildPhaseCargoCommand = "cargo doc --locked --profile $CARGO_PROFILE ; cargo check --locked --profile $CARGO_PROFILE --all-targets ; cargo build --locked --profile $CARGO_PROFILE --all-targets";
    doCheck = false;
  });

  workspaceBuild = self.cargoBuild (prev.commonArgs // {
    version = "0.0.1";
    cargoArtifacts = self.workspaceDeps;
    cargoExtraArgs = "--locked";
    doCheck = false;
  });

  workspaceTest = self.cargoTest (prev.commonArgs // {
    version = "0.0.1";
    cargoArtifacts = self.workspaceDeps;
  });

  workspaceTestDoc = self.cargoTest (self.commonArgs // {
    version = "0.0.1";
    cargoTestExtraArgs = "--doc";
    cargoArtifacts = self.workspaceDeps;
  });

  workspaceClippy = self.cargoClippy (self.commonArgs // {
    version = "0.0.1";
    cargoArtifacts = self.workspaceDeps;

    cargoClippyExtraArgs = "--all-targets --no-deps -- --deny warnings";
    doInstallCargoArtifacts = false;
  });

  workspaceDoc = self.mkCargoDerivation (self.commonArgs // {
    version = "0.0.1";
    cargoArtifacts = self.workspaceDeps;
    preConfigure = ''
      export RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links -D warnings'
    '';
    buildPhaseCargoCommand = "cargo doc --no-deps --document-private-items";
    doInstallCargoArtifacts = false;
    postInstall = ''
      cp -a target/doc/ $out
    '';
    doCheck = false;
  });

  # version of `workspaceDocs` with some nightly-only flags to publish
  workspaceDocExport = self.mkCargoDerivation (self.commonArgs // {
    version = "0.0.1";
    # no need for inheriting any artifacts, as we are using it as a one-off, and only care
    # about the docs
    cargoArtifacts = null;
    preConfigure = ''
      export RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links -Z unstable-options --enable-index-page -D warnings'
    '';
    buildPhaseCargoCommand = "cargo doc --no-deps --document-private-items";
    doInstallCargoArtifacts = false;
    installPhase = ''
      cp -a target/doc/ $out
    '';
    doCheck = false;
  });

  workspaceCargoUdepsDeps = self.buildDepsOnly (prev.commonArgsDepsOnly // {
    pname = "${self.commonArgs.pname}-udeps-deps";
    version = "0.0.1";
    nativeBuildInputs = self.commonArgs.nativeBuildInputs ++ [ pkgs.cargo-udeps ];
    # since we filtered all the actual project source, everything will definitely fail
    # but we only run this step to cache the build artifacts, so we ignore failure with `|| true`
    buildPhaseCargoCommand = "cargo udeps --all-targets --workspace --profile $CARGO_PROFILE || true";
    doCheck = false;
  });

  workspaceCargoUdeps = self.mkCargoDerivation (self.commonArgs // {
    pname = "${self.commonArgs.pname}-udeps";
    version = "0.0.1";
    # no need for inheriting any artifacts, as we are using it as a one-off, and only care
    # about the docs
    cargoArtifacts = self.workspaceCargoUdepsDeps;
    nativeBuildInputs = self.commonArgs.nativeBuildInputs ++ [ pkgs.cargo-udeps ];
    buildPhaseCargoCommand = "cargo udeps --all-targets --workspace --profile $CARGO_PROFILE";
    doInstallCargoArtifacts = false;
    doCheck = false;
  });

  workspaceAudit = self.cargoAudit (self.commonArgs // {
    version = "0.0.1";
    pname = self.commonArgs.pname + "-audit";
    inherit advisory-db;
  });

  # Build only deps, but with llvm-cov so `workspaceCov` can reuse them cached
  workspaceDepsCov = self.buildDepsOnly (self.commonArgsDepsOnly // {
    pnameSuffix = "-lcov-deps";
    version = "0.0.1";
    buildPhaseCargoCommand = "cargo llvm-cov --locked --workspace --profile $CARGO_PROFILE --no-report";
    cargoBuildCommand = "dontuse";
    cargoCheckCommand = "dontuse";
    nativeBuildInputs = self.commonArgs.nativeBuildInputs ++ [ self.cargo-llvm-cov ];
    doCheck = false;
  });

  workspaceCov = self.buildPackage (self.commonArgs // {
    pnameSuffix = "-lcov";
    version = "0.0.1";
    cargoArtifacts = self.workspaceDepsCov;
    buildPhaseCargoCommand = "mkdir -p $out ; env RUST_LOG=info,timing=debug cargo llvm-cov --locked --workspace --profile $CARGO_PROFILE --lcov --all-targets --tests --output-path $out/lcov.info --  --test-threads=$(($(nproc) * 2))";
    installPhaseCommand = "true";
    nativeBuildInputs = self.commonArgs.nativeBuildInputs ++ [ self.cargo-llvm-cov ];
    doCheck = false;
  });

  cliTestReconnect = self.mkCargoDerivation (self.commonCliTestArgs // {
    pname = "${self.commonCliTestArgs.pname}-reconnect";
    version = "0.0.1";
    cargoArtifacts = self.workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/reconnect-test.sh";
  });

  cliTestLatency = self.mkCargoDerivation (self.commonCliTestArgs // {
    pname = "${self.commonCliTestArgs.pname}-latency";
    version = "0.0.1";
    cargoArtifacts = self.workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/latency-test.sh";
  });

  cliTestCli = self.mkCargoDerivation (self.commonCliTestArgs // {
    pname = "${self.commonCliTestArgs.pname}-cli";
    version = "0.0.1";
    cargoArtifacts = self.workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/cli-test.sh";
  });

  cliLoadTestToolTest = self.mkCargoDerivation (self.commonCliTestArgs // {
    pname = "${self.commonCliTestArgs.pname}-cli";
    version = "0.0.1";
    cargoArtifacts = self.workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/load-test-tool-test.sh";
  });

  cliRustTests = self.mkCargoDerivation (self.commonCliTestArgs // {
    pname = "${self.commonCliTestArgs.pname}-rust-tests";
    version = "0.0.1";
    cargoArtifacts = self.workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/rust-tests.sh";
  });

  cliTestsAll = self.mkCargoDerivation (self.commonCliTestArgs // {
    pname = "${self.commonCliTestArgs.pname}-all";
    version = "0.0.1";
    cargoArtifacts = self.workspaceBuild;
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

  cliTestAlwaysFail = self.mkCargoDerivation (self.commonCliTestArgs // {
    pname = "${self.commonCliTestArgs.pname}-always-fail";
    version = "0.0.1";
    cargoArtifacts = self.workspaceBuild;
    buildPhaseCargoCommand = "patchShebangs ./scripts ; ./scripts/always-fail-test.sh";
  });

  wasmTests = { nativeWorkspaceBuild, wasmTarget }: self.mkCargoDerivation (self.commonCliTestArgs // {
    pname = "wasm-tests";
    version = "0.0.1";
    cargoArtifacts = nativeWorkspaceBuild;
    nativeBuildInputs = self.commonCliTestArgs.nativeBuildInputs ++ [ pkgs.firefox pkgs.wasm-bindgen-cli pkgs.geckodriver pkgs.wasm-pack ];
    buildPhaseCargoCommand = "patchShebangs ./scripts; SKIP_CARGO_BUILD=1 ./scripts/wasm-tests.sh";
    preBuild = wasmTarget.extraEnvs;
  });


  # Compile a group of packages together
  #
  # This unifies their cargo features and avoids building common dependencies multiple
  # times, but will produce a derivation with all listed packages.
  pkgsBuild = { name, pkgs, defaultBin ? null }:
    let
      # "--package x --package y" args passed to cargo
      pkgsArgs = lib.strings.concatStringsSep " " (lib.mapAttrsToList (name: value: "--package ${name}") pkgs);
      deps = self.buildDepsOnly (self.commonArgsDepsOnly // {
        pname = name;
        version = "0.0.1";
        buildPhaseCargoCommand = "cargo build --profile $CARGO_PROFILE ${pkgsArgs}";
        doCheck = false;
      });

    in

    self.buildPackage (self.commonArgs // {
      meta = { mainProgram = defaultBin; };
      pname = "${name}";
      version = "0.0.1";
      cargoArtifacts = deps;

      src = self.filterWorkspaceFiles self.commonSrc;
      cargoExtraArgs = pkgsArgs;

      # if needed we will check the whole workspace at once with `workspaceBuild`
      doCheck = false;
    });


  # Cross-compile a group of packages together.
  #
  # This unifies their cargo features and avoids building common dependencies multiple
  # times, but will produce a derivation with all listed packages.
  pkgsCrossBuild = { name, pkgs, target }:
    if target == null then
      self.pkgsBuild
        {
          inherit name pkgs;
        }
    else
      let
        # "--package x --package y" args passed to cargo
        pkgsArgs = lib.strings.concatStringsSep " " (lib.mapAttrsToList (name: value: "--package ${name}") pkgs);
        deps = self.buildDepsOnly (self.commonArgsDepsOnly // {
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
      self.buildPackage (self.commonArgs // {
        pname = "${name}-${target.name}";
        version = "0.0.1";
        cargoArtifacts = deps;

        src = self.filterWorkspaceFiles self.commonSrc;
        cargoExtraArgs = "--target ${target.name} ${pkgsArgs}";

        # if needed we will check the whole workspace at once with `workspaceBuild`
        doCheck = false;
        preBuild = ''
          patchShebangs .cargo/
        '' + target.extraEnvs;
      });

  fedimint-pkgs = self.pkgsBuild {
    name = "fedimint-pkgs";

    pkgs = {
      fedimintd = { };
      fedimint-cli = { };
      fedimint-tests = { };
    };

    defaultBin = "fedimintd";
  };

  gateway-pkgs = self.pkgsBuild {
    name = "gateway-pkgs";

    pkgs = {
      ln-gateway = { };
      gateway-cli = { };
    };

  };

  client-pkgs = { target ? null }: self.pkgsCrossBuild {
    name = "client-pkgs";
    inherit target;

    pkgs = {
      fedimint-client-legacy = { };
    } // lib.optionalAttrs (target == null || target.name != "wasm32-unknown-unknown") {
      # broken on wasm32
      fedimint-sqlite = { };
    };
  };

  fedimint-dbtool-pkgs = self.pkgsBuild {
    name = "fedimint-dbtool-pkgs";
    pkgs = {
      fedimint-dbtool = { };
    };
  };

  devimint = self.pkgsBuild {
    name = "devimint";
    pkgs = {
      devimint = { };
    };
  };

  fedimint-load-test-tool = self.pkgsBuild {
    name = "fedimint-load-test-tool";
    pkgs = {
      fedimint-load-test-tool = { };
    };
  };
})

