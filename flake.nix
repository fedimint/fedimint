{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.05";
    crane.url = "github:ipetkov/crane";
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
  };

  outputs = { self, nixpkgs, flake-utils, flake-compat, fenix, crane }:
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

        fenix-toolchain = (fenix.packages.${system}.complete.withComponents [
          "rustc"
          "cargo"
          "clippy"
          "rust-analysis"
          "rust-src"
          "rustfmt"
          "llvm-tools-preview"
        ]);

        fenix-channel = fenix.packages.${system}.stable;

        craneLib = crane.lib.${system}.overrideToolchain fenix-toolchain;

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
          in
          lib.cleanSourceWith {
            filter = (path: type:
              let
                relPath = lib.removePrefix basePath (toString path);
                includePath =
                  (type == "directory" && builtins.match "^[^/]+$" relPath != null) ||
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
          pname = "minimint-dependencies";
          doCheck = false;
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

        workspaceBuild = craneLib.cargoBuild (commonArgs // {
          cargoArtifacts = workspaceDeps;
          doCheck = false;
        });

        workspaceTest = craneLib.cargoBuild (commonArgs // {
          cargoArtifacts = workspaceBuild;
          doCheck = true;
        });

        # Note: can't use `cargoClippy` because it implies `--all-targets`, while
        # we can't build benches on stable
        # See: https://github.com/ipetkov/crane/issues/64
        workspaceClippy = craneLib.cargoBuild (commonArgs // {
          cargoArtifacts = workspaceBuild;

          cargoBuildCommand = "cargo clippy --profile release --lib --bins --tests --examples --workspace -- --deny warnings";
          doInstallCargoArtifacts = false;
          doCheck = false;
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

        llvmCovWorkspace = craneLib.cargoBuild (commonArgs // {
          cargoArtifacts = workspaceDeps;
          cargoBuildCommand = "mkdir -p $out && cargo llvm-cov --workspace --lcov --output-path $out/lcov.info";
          doCheck = true;
          nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ cargo-llvm-cov ];
        });

        minimint = pkg {
          name = "minimint";
          dir = "minimint";
          extraDirs = [
            "client/cli"
            "client/client-lib"
            "client/clientd"
            "crypto/tbs"
            "ln-gateway"
            "minimint-api"
            "minimint-core"
            "minimint-derive"
            "modules/minimint-ln"
            "modules/minimint-mint"
            "modules/minimint-wallet"
          ];
        };

        ln-gateway = pkg {
          name = "ln_gateway";
          dir = "ln-gateway";
          extraDirs = [
            "crypto/tbs"
            "client/client-lib"
            "client/clientd"
            "client/cli"
            "modules/minimint-ln"
            "minimint"
            "minimint-api"
            "minimint-core"
            "minimint-derive"
            "modules/minimint-mint"
            "modules/minimint-wallet"
          ];
        };

        mint-client-cli = pkg {
          name = "mint-client-cli";
          dir = "client/cli";
          extraDirs = [
            "client/clientd"
            "client/client-lib"
            "crypto/tbs"
            "minimint-api"
            "minimint-core"
            "minimint-derive"
            "modules/minimint-ln"
            "modules/minimint-mint"
            "modules/minimint-wallet"
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
            "minimint-api"
            "minimint-core"
            "minimint-derive"
            "modules/minimint-ln"
            "modules/minimint-mint"
            "modules/minimint-wallet"
          ];
        };

        minimint-tests = pkg {
          dir = "integrationtests";
          extraDirs = [
            "client/cli"
            "client/client-lib"
            "client/clientd"
            "crypto/tbs"
            "ln-gateway"
            "minimint"
            "minimint-api"
            "minimint-core"
            "minimint-derive"
            "modules/minimint-ln"
            "modules/minimint-mint"
            "modules/minimint-wallet"
          ];
        };
      in
      {
        packages = {
          default = minimint.package;

          minimint = minimint.package;
          minimint-tests = minimint-tests.package;
          ln-gateway = ln-gateway.package;
          clientd = clientd.package;
          mint-client-cli = mint-client-cli.package;

          deps = workspaceDeps;
          workspaceBuild = workspaceBuild;
          workspaceClippy = workspaceClippy;
          workspaceTest = workspaceTest;
          workspaceCov = llvmCovWorkspace;

          cli-test = {
            latency = cliTestLatency;
            cli = cliTestCli;
            clientd = cliTestClientd;
            rust-tests = cliRustTests;
          };

          container = {
            minimint = minimint.container;
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
                cargo-llvm-cov
                cargo-udeps

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
                tmux
                tmuxinator

                minimint.package
                minimint-tests.package
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
          };
      });
}
