{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.05";
    crane.url = "github:ipetkov/crane?rev=2d5e7fbfcee984424fe4ad4b3b077c62d18fe1cf"; # v0.6
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

        clightning-dev = pkgs.clightning.overrideAttrs (oldAttrs: {
          configureFlags = [ "--enable-developer" "--disable-valgrind" ];
        } // pkgs.lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
          NIX_CFLAGS_COMPILE = "-Wno-stringop-truncation";
        });

        fenix-channel = fenix.packages.${system}.stable;

        fenix-toolchain = (fenix-channel.withComponents [
          "rustc"
          "cargo"
          "clippy"
          "rust-analysis"
          "rust-src"
          "rustfmt"
          "llvm-tools-preview"
        ]);

        craneLib = crane.lib.${system}.overrideToolchain fenix-toolchain;

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
                    ([ "Cargo.lock" "Cargo.toml" ".*/Cargo.toml" ] ++ builtins.concatLists (map (name: [ name "${name}/.*" ]) modules));
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
        filterWorkspaceDepsBuildFiles = src: filterSrcWithRegexes [ "Cargo.lock" "Cargo.toml" ".*/Cargo.toml" ] src;

        # Filter only files relevant to building the workspace
        filterWorkspaceFiles = src: filterSrcWithRegexes [ "Cargo.lock" "Cargo.toml" ".*/Cargo.toml" ".*\.rs" ] src;

        # Like `filterWorkspaceFiles` but with `./scripts/` included
        filterWorkspaceCliTestFiles = src: filterSrcWithRegexes [ "Cargo.lock" "Cargo.toml" ".*/Cargo.toml" ".*\.rs" "scripts/.*" ] src;

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
            fenix-channel.rustc
            fenix-channel.clippy
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


        # a function to define cargo&nix package, listing
        # all the dependencies (as dir) to help limit the
        # amount of things that need to rebuild when some
        # file change
        pkg = { name ? null, dir, port ? 8000, extraDirs ? [ ] }: rec {
          package = craneLib.buildPackage (commonArgs // {
            cargoArtifacts = workspaceDeps;

            src = filterModules ([ dir ] ++ extraDirs) ./.;

            # if needed we will check the whole workspace at once with `workspaceBuild`
            doCheck = false;
          } // lib.optionalAttrs (name != null) {
            pname = name;
            cargoExtraArgs = "--bin ${name}";
          });

          container = pkgs.dockerTools.buildLayeredImage {
            name = name;
            contents = [ package ];
            config = {
              Cmd = [
                "${package}/bin/${name}"
              ];
              ExposedPorts = {
                "${builtins.toString port}/tcp" = { };
              };
            };
          };
        };

        fedimintd = pkg {
          name = "fedimintd";
          dir = "fedimint";
          extraDirs = [
            "crypto/tbs"
            "ln-gateway"
            "client/client-lib"
            "fedimint-api"
            "fedimint-core"
            "fedimint-derive"
            "modules/fedimint-ln"
            "modules/fedimint-mint"
            "modules/fedimint-wallet"
          ];
        };

        ln-gateway = pkg {
          name = "ln_gateway";
          dir = "ln-gateway";
          extraDirs = [
            "crypto/tbs"
            "client/client-lib"
            "modules/fedimint-ln"
            "fedimint"
            "fedimint-api"
            "fedimint-core"
            "fedimint-derive"
            "modules/fedimint-mint"
            "modules/fedimint-wallet"
          ];
        };

        mint-client-cli = pkg {
          name = "mint-client-cli";
          dir = "client/cli";
          extraDirs = [
            "client/clientd"
            "client/client-lib"
            "crypto/tbs"
            "fedimint-api"
            "fedimint-core"
            "fedimint-derive"
            "modules/fedimint-ln"
            "modules/fedimint-mint"
            "modules/fedimint-wallet"
          ];
        };

        clientd = pkg {
          name = "clientd";
          dir = "client/clientd";
          extraDirs = [
            "client/cli"
            "client/client-lib"
            "client/clientd"
            "crypto/tbs"
            "fedimint-api"
            "fedimint-core"
            "fedimint-derive"
            "modules/fedimint-ln"
            "modules/fedimint-mint"
            "modules/fedimint-wallet"
          ];
        };

        fedimint-tests = pkg {
          dir = "integrationtests";
          extraDirs = [
            "client/cli"
            "client/client-lib"
            "client/clientd"
            "crypto/tbs"
            "ln-gateway"
            "fedimint"
            "fedimint-api"
            "fedimint-core"
            "fedimint-derive"
            "modules/fedimint-ln"
            "modules/fedimint-mint"
            "modules/fedimint-wallet"
          ];
        };
      in
      {
        packages = {
          default = fedimintd.package;

          fedimintd = fedimintd.package;
          fedimint-tests = fedimint-tests.package;
          ln-gateway = ln-gateway.package;
          clientd = clientd.package;
          mint-client-cli = mint-client-cli.package;

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

          container = {
            fedimintd = fedimintd.container;
          };
        };

        checks = {
          inherit
            workspaceBuild
            workspaceClippy;
        };

        devShells =
          {
            # The default shell - meant to developers working on the project,
            # so notably not building any project binaries, but including all
            # the settings and tools neccessary to build and work with the codebase.
            default = pkgs.mkShell {
              buildInputs = workspaceDeps.buildInputs;
              nativeBuildInputs = with pkgs; workspaceDeps.nativeBuildInputs ++ [
                fenix-toolchain
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
              RUST_SRC_PATH = "${fenix-channel.rust-src}/lib/rustlib/src/rust/library";
              LIBCLANG_PATH = "${pkgs.libclang.lib}/lib/";

              shellHook = ''
                # auto-install git hooks
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

            # Integration test shell - meant for running all the integration tests
            # (usually from the CI) # which meants it includes all the project binaries,
            # but it doesn't include dev tools etc.
            integrationTests = pkgs.mkShell {

              buildInputs = workspaceDeps.buildInputs;
              nativeBuildInputs = with pkgs; workspaceDeps.nativeBuildInputs ++ [
                bc
                perl
                bitcoind
                clightning-dev
                jq
                procps
                # This is required to prevent a mangled bash shell in nix develop
                # see: https://discourse.nixos.org/t/interactive-bash-with-nix-develop-flake/15486
                (hiPrio pkgs.bashInteractive)
                tmux
                tmuxinator
                coreutils

                fedimintd.package
                fedimint-tests.package
                ln-gateway.package
                mint-client-cli.package
                clientd.package
              ];

              LIBCLANG_PATH = "${pkgs.libclang.lib}/lib/";
            };

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
