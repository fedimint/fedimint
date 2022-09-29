{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.05";
    crane.url = "github:ipetkov/crane?rev=755acd231a7de182fdc772bee1b2a1f21d4ec9ed"; # https://github.com/ipetkov/crane/releases/tag/v0.7.0
    crane.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, flake-compat, fenix, crane, advisory-db }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
        lib = pkgs.lib;
        stdenv = pkgs.stdenv;

        clightning-dev = pkgs.clightning.overrideAttrs (oldAttrs: {
          configureFlags = [ "--enable-developer" "--disable-valgrind" ];
        } // pkgs.lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
          NIX_CFLAGS_COMPILE = "-Wno-stringop-truncation";
        });

        isArch64Darwin = stdenv.isAarch64 || stdenv.isDarwin;

        # Env vars we need for wasm32 cross compilation
        wasm32CrossEnvVars = ''
          export CC_wasm32_unknown_unknown="${pkgs.llvmPackages_14.clang-unwrapped}/bin/clang-14"
          export CFLAGS_wasm32_unknown_unknown="-I ${pkgs.llvmPackages_14.libclang.lib}/lib/clang/14.0.1/include/"
        '' + (if isArch64Darwin then
          ''
            export AR_wasm32_unknown_unknown="${pkgs.llvmPackages_14.llvm}/bin/llvm-ar"
          '' else
          ''
          '');

        # All the environment variables we need for all android cross compilation targets
        androidCrossEnvVars = ''
          # Note: rockdb seems to require uint128_t, which is not supported on 32-bit Android: https://stackoverflow.com/a/25819240/134409 (?)
          export LLVM_CONFIG_PATH="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-config"

          export CC_armv7_linux_androideabi="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
          export CXX_armv7_linux_androideabi="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++"
          export LD_armv7_linux_androideabi="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/arm-linux-androideabi/bin/ld"
          export LDFLAGS_armv7_linux_androideabi="-L ${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/arm-linux-androideabi/30/ -L ${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/lib/gcc/arm-linux-androideabi/4.9.x/ -L ${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/arm-linux-androideabi/"

          export CC_aarch64_linux_android="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
          export CXX_aarch64_linux_android="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++"
          export LD_aarch64_linux_android="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/aarch64-linux-android/bin/ld"
          export LDFLAGS_aarch64_linux_android="-L ${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/30/ -L ${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/lib/gcc/aarch64-linux-android/4.9.x/ -L ${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/"

          export CC_x86_64_linux_android="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
          export CXX_x86_64_linux_android="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++"
          export LD_x86_64_linux_android="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/aarch64-linux-android/bin/ld"
          export LDFLAGS_x86_64_linux_android="-L ${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/x86_64-linux-android/30/ -L ${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/lib/gcc/x86_64-linux-android/4.9.x/ -L ${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/x86_64-linux-android/"

          export CC_i686_linux_android="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
          export CXX_i686_linux_android="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++"
          export LD_i686_linux_android="${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/aarch64-linux-android/bin/ld"
          export LDFLAGS_i686_linux_android="-L ${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/i686-linux-android/30/ -L ${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/lib/gcc/i686-linux-android/4.9.x/ -L ${androidComposition.ndk-bundle}/libexec/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/i686-linux-android/"
        '';

        # NDK we use for android cross compilation
        androidComposition = pkgs.androidenv.composeAndroidPackages {
          includeNDK = true;
        };

        # Definitions of all the cross-compilation targets we support.
        # Later mapped over to conveniently loop over all posibilities.
        crossTargets =
          builtins.mapAttrs
            (attr: target: { attr = attr; extraEnvs = ""; } // target)
            {
              "wasm32" = {
                name = "wasm32-unknown-unknown";
                extraEnvs = wasm32CrossEnvVars;
              };
              "armv7-android" = {
                name = "armv7-linux-androideabi";
                extraEnvs = androidCrossEnvVars;
              };
              "aarch64-android" = {
                name = "aarch64-linux-android";
                extraEnvs = androidCrossEnvVars;
              };
              "i686-android" = {
                name = "i686-linux-android";
                extraEnvs = androidCrossEnvVars;
              };
              "x86_64-android" = {
                name = "x86_64-linux-android";
                extraEnvs = androidCrossEnvVars;
              };
            };

        fenixChannel = fenix.packages.${system}.stable;

        fenixToolchain = (fenixChannel.withComponents [
          "rustc"
          "cargo"
          "clippy"
          "rust-analysis"
          "rust-src"
          "rustfmt"
          "llvm-tools-preview"
        ]);

        fenixToolchainCrossAll = with fenix.packages.${system}; combine ([
          stable.cargo
          stable.rustc
        ] ++ (lib.attrsets.mapAttrsToList
          (attr: target: targets.${target.name}.stable.rust-std)
          crossTargets));

        fenixToolchainCross = builtins.mapAttrs
          (attr: target: with fenix.packages.${system}; combine [
            stable.cargo
            stable.rustc
            targets.${target.name}.stable.rust-std
          ])
          crossTargets
        ;

        craneLib = crane.lib.${system}.overrideToolchain fenixToolchain;

        craneLibCross = builtins.mapAttrs
          (attr: target: crane.lib.${system}.overrideToolchain fenixToolchainCross.${attr})
          crossTargets
        ;

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

        # some extra utilities that cli-tests require
        cliTestsDeps = with pkgs; [
          bc
          bitcoind
          clightning-dev
          jq
          netcat
          perl
          procps
          bash
          which
        ];

        # filter source code at path `src` to include only the list of `modules`
        filterModules = modules: src:
          let
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
                  # traverse only into directories that somewhere in there contain `Cargo.toml` file, or were explicitily whitelisted
                  (type == "directory" && lib.any (cargoTomlPath: lib.strings.hasPrefix relPath cargoTomlPath) relPathAllCargoTomlFiles) ||
                  lib.any
                    (re: builtins.match re relPath != null)
                    ([ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".*/Cargo.toml" ] ++ builtins.concatLists (map (name: [ name "${name}/.*" ]) modules));
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
        filterWorkspaceDepsBuildFiles = src: filterSrcWithRegexes [ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".*/Cargo.toml" ] src;

        # Filter only files relevant to building the workspace
        filterWorkspaceFiles = src: filterSrcWithRegexes [ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".*/Cargo.toml" ".*\.rs" ] src;

        # Like `filterWorkspaceFiles` but with `./scripts/` included
        filterWorkspaceCliTestFiles = src: filterSrcWithRegexes [ "Cargo.lock" "Cargo.toml" ".cargo" ".cargo/.*" ".*/Cargo.toml" ".*\.rs" "scripts/.*" ] src;

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


        commonArgs = {
          src = filterWorkspaceFiles ./.;

          buildInputs = with pkgs; [
            clang
            gcc
            openssl
            pkg-config
            perl
          ] ++ lib.optionals stdenv.isDarwin [
            libiconv
            darwin.apple_sdk.frameworks.Security
          ] ++ lib.optionals (!(stdenv.isAarch64 || stdenv.isDarwin)) [
            # mold is currently broken on ARM and MacOS
            mold
          ];

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          # copy over the linker/ar wrapper scripts which by default would get
          # stripped by crane
          dummySrc = craneLib.mkDummySrc {
            src = ./.;
            extraDummyScript = ''
              cp -r ${./.cargo} -T $out/.cargo
            '';
          };

          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib/";
          CI = "true";
          HOME = "/tmp";
        };

        commonCliTestArgs = commonArgs // {
          src = filterWorkspaceCliTestFiles ./.;
          nativeBuildInputs = commonArgs.nativeBuildInputs ++ cliTestsDeps;
          # there's no point saving the `./target/` dir
          doInstallCargoArtifacts = false;
          # the command is a test, no need to run any other tests
          doCheck = false;
        };

        workspaceDeps = craneLib.buildDepsOnly (commonArgs // {
          src = filterWorkspaceDepsBuildFiles ./.;
          pname = "workspace-deps";
          buildPhaseCargoCommand = "cargo doc && cargo check --profile release --all-targets && cargo build --profile release --all-targets";
          doCheck = false;
        });

        workspaceBuild = craneLib.cargoBuild (commonArgs // {
          pname = "workspace-build";
          cargoArtifacts = workspaceDeps;
          doCheck = false;
        });

        workspaceTest = craneLib.cargoBuild (commonArgs // {
          pname = "workspace-test";
          cargoBuildCommand = "true";
          cargoArtifacts = workspaceDeps;
          doCheck = true;
        });

        workspaceClippy = craneLib.cargoClippy (commonArgs // {
          pname = "workspace-clippy";
          cargoArtifacts = workspaceDeps;

          cargoClippyExtraArgs = "--all-targets --no-deps -- --deny warnings";
          doInstallCargoArtifacts = false;
          doCheck = false;
        });

        workspaceDoc = craneLib.cargoBuild (commonArgs // {
          pname = "workspace-doc";
          cargoArtifacts = workspaceDeps;
          cargoBuildCommand = "env RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links' cargo doc --no-deps --document-private-items && cp -a target/doc $out";
          doCheck = false;
        });

        workspaceAudit = craneLib.cargoAudit (commonArgs // {
          pname = "workspace-clippy";
          inherit advisory-db;
        });

        # Build only deps, but with llvm-cov so `workspaceCov` can reuse them cached
        workspaceDepsCov = craneLib.buildDepsOnly (commonArgs // {
          pname = "workspace-deps-llvm-cov";
          src = filterWorkspaceDepsBuildFiles ./.;
          cargoBuildCommand = "cargo llvm-cov --workspace";
          nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ cargo-llvm-cov ];
          doCheck = false;
        });

        workspaceCov = craneLib.cargoBuild (commonArgs // {
          pname = "workspace-llvm-cov";
          cargoArtifacts = workspaceDepsCov;
          # TODO: as things are right now, the integration tests can't run in parallel
          cargoBuildCommand = "mkdir -p $out && env RUST_TEST_THREADS=1 cargo llvm-cov --workspace --lcov --output-path $out/lcov.info";
          doCheck = false;
          nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ cargo-llvm-cov ];
        });

        cliTestReconnect = craneLib.cargoBuild (commonCliTestArgs // {
          cargoArtifacts = workspaceBuild;
          cargoBuildCommand = "patchShebangs ./scripts && ./scripts/reconnect-test.sh";
        });

        cliTestLatency = craneLib.cargoBuild (commonCliTestArgs // {
          cargoArtifacts = workspaceBuild;
          cargoBuildCommand = "patchShebangs ./scripts && ./scripts/latency-test.sh";
          doInstallCargoArtifacts = false;
        });

        cliTestCli = craneLib.cargoBuild (commonCliTestArgs // {
          cargoArtifacts = workspaceBuild;
          cargoBuildCommand = "patchShebangs ./scripts && ./scripts/cli-test.sh";
        });

        cliTestClientd = craneLib.cargoBuild (commonCliTestArgs // {
          cargoArtifacts = workspaceBuild;
          cargoBuildCommand = "patchShebangs ./scripts && ./scripts/clientd-tests.sh";
        });

        cliRustTests = craneLib.cargoBuild (commonCliTestArgs // {
          cargoArtifacts = workspaceBuild;
          cargoBuildCommand = "patchShebangs ./scripts && ./scripts/rust-tests.sh";
        });


        pkg = { name, dirs, bin }:
          let
            deps = craneLib.buildDepsOnly (commonArgs // {
              src = filterWorkspaceDepsBuildFiles ./.;
              pname = "pkg-${name}-deps";
              buildPhaseCargoCommand = "cargo build --profile release --package ${name}";
              doCheck = false;
            });

          in

          craneLib.buildPackage (commonArgs // {
            meta = { mainProgram = bin; };
            pname = "pkg-${name}";
            cargoArtifacts = workspaceDeps;

            src = filterModules dirs ./.;
            cargoExtraArgs = "--package ${name}";

            # if needed we will check the whole workspace at once with `workspaceBuild`
            doCheck = false;
          });


        pkgCross = { name, dirs, target }:
          let
            craneLib = craneLibCross.${target.attr};
            deps = craneLib.buildDepsOnly (commonArgs // {
              src = filterWorkspaceDepsBuildFiles ./.;
              pname = "pkg-${name}-${target.attr}-deps";
              buildPhaseCargoCommand = "cargo build --profile release --target ${target.name} --package ${name}";
              doCheck = false;

              preBuild = ''
                chmod +x .cargo/ar.*
                chmod +x .cargo/ld.*
                patchShebangs .cargo/
              '' + target.extraEnvs;
            });

          in
          craneLib.buildPackage (commonArgs // {
            pname = "pkg-${name}-${target.attr}";
            cargoArtifacts = deps;

            src = filterModules dirs ./.;
            cargoExtraArgs = "--package ${name} --target ${target.name}";

            # if needed we will check the whole workspace at once with `workspaceBuild`
            doCheck = false;
            preBuild = ''
              chmod +x .cargo/ar.*
              chmod +x .cargo/ld.*
              patchShebangs .cargo/
            '' + target.extraEnvs;
          });

        fedimintd = pkg {
          name = "fedimintd";
          bin = "fedimintd";
          dirs = [
            "client/client-lib"
            "crypto/tbs"
            "fedimintd"
            "fedimint-api"
            "fedimint-build"
            "fedimint-core"
            "fedimint-derive"
            "fedimint-rocksdb"
            "fedimint-server"
            "ln-gateway"
            "modules/fedimint-ln"
            "modules/fedimint-mint"
            "modules/fedimint-wallet"
          ];
        };

        ln-gateway = pkg {
          name = "ln-gateway";
          bin = "ln-gateway";
          dirs = [
            "crypto/tbs"
            "client/client-lib"
            "modules/fedimint-ln"
            "fedimint-api"
            "fedimint-core"
            "fedimint-derive"
            "fedimint-rocksdb"
            "fedimint-server"
            "fedimint-build"
            "ln-gateway"
            "modules/fedimint-mint"
            "modules/fedimint-wallet"
          ];
        };

        mint-client-cli = pkg {
          name = "mint-client-cli";
          bin = "mint-client-cli";
          dirs = [
            "client/clientd"
            "client/client-lib"
            "client/cli"
            "crypto/tbs"
            "fedimint-api"
            "fedimint-core"
            "fedimint-derive"
            "fedimint-rocksdb"
            "fedimint-build"
            "modules/fedimint-ln"
            "modules/fedimint-mint"
            "modules/fedimint-wallet"
          ];
        };

        mint-client = { target }: pkgCross {
          name = "mint-client";
          inherit target;
          dirs = [
            "client/client-lib"
            "crypto/tbs"
            "fedimint-api"
            "fedimint-core"
            "fedimint-derive"
            "fedimint-rocksdb"
            "modules/fedimint-ln"
            "modules/fedimint-mint"
            "modules/fedimint-wallet"
          ];
        };

        clientd = pkg {
          name = "clientd";
          bin = "clientd";
          dirs = [
            "client/cli"
            "client/client-lib"
            "client/clientd"
            "crypto/tbs"
            "fedimint-api"
            "fedimint-core"
            "fedimint-derive"
            "fedimint-rocksdb"
            "fedimint-build"
            "modules/fedimint-ln"
            "modules/fedimint-mint"
            "modules/fedimint-wallet"
          ];
        };

        fedimint-tests = pkg {
          name = "fedimint-tests";
          extraDirs = [
            "client/cli"
            "client/client-lib"
            "client/clientd"
            "crypto/tbs"
            "ln-gateway"
            "fedimint-api"
            "fedimint-core"
            "fedimint-derive"
            "fedimint-server"
            "integrationtests"
            "modules/fedimint-ln"
            "modules/fedimint-mint"
            "modules/fedimint-wallet"
          ];
        };

        # Replace placeholder git hash in a binary
        #
        # To avoid impurity, we use a git hash placeholder when building binaries
        # and then replace them with the real git hash in the binaries themselves.
        replace-git-hash = { package, name }:
          let
            # the git hash placeholder we use in `build.rs` scripts when
            # building in Nix (to preserve purity)
            hash-placeholder = "01234569afbe457afa1d2683a099c7af48a523c1";
            # the hash we will set if the tree is dirty;
            dirty-hash = "0000000000000000000000000000000000000000";
            # git hash to set (passed by Nix if the tree is clean, or `dirty-hash` when dirty)
            git-hash = if (self ? rev) then self.rev else dirty-hash;
          in
          stdenv.mkDerivation {
            inherit system;
            inherit name;

            dontUnpack = true;

            installPhase = ''
              cp -a ${package} $out
              for path in `find $out -type f -executable`; do
                # need to use a temporary file not to overwrite source as we are reading it
                bbe -e 's/${hash-placeholder}/${git-hash}/' $path -o ./tmp || exit 1
                chmod +w $path
                # use cat to keep all the original permissions etc as they were
                cat ./tmp > "$path"
                chmod -w $path
              done
            '';

            buildInputs = [ pkgs.bbe ];
          };

      in
      {
        packages = {
          default = fedimintd;

          fedimintd = replace-git-hash { name = "fedimint"; package = fedimintd; };
          fedimint-tests = fedimint-tests;
          ln-gateway = replace-git-hash { name = "ln-gateway"; package = ln-gateway; };
          clientd = replace-git-hash { name = "clientd"; package = clientd; };
          mint-client-cli = replace-git-hash { name = "mint-client-cli"; package = mint-client-cli; };

          inherit workspaceDeps
            workspaceBuild
            workspaceClippy
            workspaceTest
            workspaceDoc
            workspaceCov
            workspaceAudit;

          cli-test = {
            reconnect = cliTestReconnect;
            latency = cliTestLatency;
            cli = cliTestCli;
            clientd = cliTestClientd;
            rust-tests = cliRustTests;
          };

          cross = builtins.mapAttrs
            (attr: target: {
              mint-client = mint-client { inherit target; };
            })
            crossTargets;


          container = {
            fedimintd = pkgs.dockerTools.buildLayeredImage {
              name = "fedimint";
              contents = [ fedimintd ];
              config = {
                Cmd = [
                  "${fedimintd}/bin/fedimintd"
                ];
                ExposedPorts = {
                  "${builtins.toString 8080}/tcp" = { };
                };
              };
            };
          };
        };

        checks = {
          inherit
            workspaceBuild
            workspaceClippy;
        };

        devShells =

          let shellCommon = {
            buildInputs = commonArgs.buildInputs;
            nativeBuildInputs = with pkgs; commonArgs.nativeBuildInputs ++ [
              fenix.packages.${system}.rust-analyzer
              cargo-llvm-cov
              cargo-udeps

              # This is required to prevent a mangled bash shell in nix develop
              # see: https://discourse.nixos.org/t/interactive-bash-with-nix-develop-flake/15486
              (hiPrio pkgs.bashInteractive)
              tmux
              tmuxinator

              # Nix
              pkgs.nixpkgs-fmt
              pkgs.shellcheck
              pkgs.rnix-lsp
              pkgs.nodePackages.bash-language-server
            ] ++ cliTestsDeps;
            RUST_SRC_PATH = "${fenixChannel.rust-src}/lib/rustlib/src/rust/library";
            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib/";

            shellHook = ''
              # auto-install git hooks
              if [[ ! -d .git/hooks ]]; then mkdir .git/hooks; fi
              for hook in misc/git-hooks/* ; do ln -sf "../../$hook" "./.git/hooks/" ; done
              ${pkgs.git}/bin/git config commit.template misc/git-hooks/commit-template.txt

              # workaround https://github.com/rust-lang/cargo/issues/11020
              cargo_cmd_bins=( $(ls $HOME/.cargo/bin/cargo-{clippy,udeps,llvm-cov} 2>/dev/null) )
              if (( ''${#cargo_cmd_bins[@]} != 0 )); then
                echo "Warning: Detected binaries that might conflict with reproducible environment: ''${cargo_cmd_bins[@]}" 1>&2
                echo "Warning: Considering deleting them. See https://github.com/rust-lang/cargo/issues/11020 for details" 1>&2
              fi
            '';
          };

          in
          {
            # The default shell - meant to developers working on the project,
            # so notably not building any project binaries, but including all
            # the settings and tools neccessary to build and work with the codebase.
            default = pkgs.mkShell (shellCommon
              // {
              nativeBuildInputs = shellCommon.nativeBuildInputs ++ [ fenixToolchain ];
            });


            # Shell with extra stuff to support cross-compilation with `cargo build --target <target>`
            #
            # This will pull extra stuff so to save time and download time to most common developers,
            # was moved into another shell.
            cross = pkgs.mkShell (shellCommon // {
              nativeBuildInputs = shellCommon.nativeBuildInputs ++ [ fenixToolchainCrossAll ];

              shellHook = shellCommon.shellHook +

                # Android NDK not available for Arm MacOS
                (if isArch64Darwin then "" else androidCrossEnvVars)
                + wasm32CrossEnvVars;
            });

            # this shell is used only in CI, so it should contain minimum amount
            # of stuff to avoid building and caching things we don't need
            lint = pkgs.mkShell {
              nativeBuildInputs = [
                pkgs.rustfmt
                pkgs.nixpkgs-fmt
                pkgs.shellcheck
                pkgs.git
              ];
            };

            replit = pkgs.mkShell {
              nativeBuildInputs = with pkgs; [
                pkg-config
                openssl
              ];
              LIBCLANG_PATH = "${pkgs.libclang.lib}/lib/";
            };
          };
      });
}
