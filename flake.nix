{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixpkgs-kitman.url = "github:jkitman/nixpkgs/add-esplora-pkg";
    crane.url = "github:ipetkov/crane?ref=master&ref=953b70da2813fb882c39890f2514e7db76fc8843";
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

  outputs = { self, nixpkgs, nixpkgs-unstable, nixpkgs-kitman, flake-utils, flake-compat, fenix, crane, advisory-db }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };
          pkgs-kitman = import nixpkgs-kitman {
            inherit system;
          };

          pkgs-unstable = import nixpkgs-unstable {
            inherit system;
          };

          lib = pkgs.lib;

          stdenv = pkgs.stdenv;

          clightning-dev = pkgs.clightning.overrideAttrs (oldAttrs: {
            configureFlags = [ "--enable-developer" "--disable-valgrind" ];
          } // pkgs.lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
            NIX_CFLAGS_COMPILE = "-Wno-stringop-truncation";
          });

          # `moreutils/bin/parallel` and `parallel/bin/parallel` conflict, so just use
          # the binary we need from `moreutils`
          moreutils-ts = pkgs.writeShellScriptBin "ts" "exec ${pkgs.moreutils}/bin/ts \"$@\"";

          isArch64Darwin = stdenv.isAarch64 || stdenv.isDarwin;

          toolchain = import ./flake.toolchain.nix
            {

              inherit pkgs lib system stdenv fenix crane;
            };


          craneBuild = import ./flake.crane.nix
            {
              inherit pkgs pkgs-kitman clightning-dev advisory-db lib moreutils-ts;
            };

          craneBuildNative = craneBuild toolchain.craneLibNative;
          craneBuildNativeDocExport = craneBuild toolchain.craneLibNativeDocExport;
          craneBuildCross = target: craneBuild toolchain.craneLibCross.${target};

          # Replace placeholder git hash in a binary
          #
          # To avoid impurity, we use a git hash placeholder when building binaries
          # and then replace them with the real git hash in the binaries themselves.
          replaceGitHash = { package, name }:
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

          # Create a package that contains only one `bin`ary from an input `pkg`
          #
          # For efficiency we built some binaries togetherr (like fedimintd + fedimint-cli),
          # but we would like to expose them separately.
          pickBinary = { pkg, bin }:
            stdenv.mkDerivation {
              inherit system;
              name = bin;

              dontUnpack = true;

              installPhase = ''
                mkdir -p $out/bin
                cp -a ${pkg}/bin/${bin} $out/bin/${bin}
              '';
            };

          # outputs that do something over the whole workspace
          workspaceOutputs = {
            workspaceDeps = craneBuildNative.workspaceDeps;
            workspaceBuild = craneBuildNative.workspaceBuild;
            workspaceClippy = craneBuildNative.workspaceClippy;
            workspaceTest = craneBuildNative.workspaceTest;
            workspaceTestDoc = craneBuildNative.workspaceTestDoc;
            workspaceDoc = craneBuildNative.workspaceDoc;
            workspaceDocExport = craneBuildNativeDocExport.workspaceDocExport;
            workspaceCargoUdeps = craneBuildNativeDocExport.workspaceCargoUdeps;
            workspaceCov = craneBuildNative.workspaceCov;
            workspaceAudit = craneBuildNative.workspaceAudit;
          };

          # outputs that build a particular Rust package
          rustPackageOutputs = {
            default = craneBuildNative.fedimint-pkgs;

            fedimint-pkgs = craneBuildNative.fedimint-pkgs;
            gateway-pkgs = craneBuildNative.gateway-pkgs;
            client-pkgs = craneBuildNative.client-pkgs { };
          };

          # rust packages outputs with git hash replaced
          rustPackageOutputsFinal = builtins.mapAttrs (name: package: replaceGitHash { inherit name package; }) rustPackageOutputs;

          cli-test = {
            all = craneBuildNative.cliTestsAll;
            reconnect = craneBuildNative.cliTestReconnect;
            upgrade = craneBuildNative.cliTestUpgrade;
            latency = craneBuildNative.cliTestLatency;
            cli = craneBuildNative.cliTestCli;
            rust-tests = craneBuildNative.cliRustTests;
            always-fail = craneBuildNative.cliTestAlwaysFail;
          };

          # packages we expose from our flake (note: we also expose `legacyPackages` for hierarchical outputs)
          packages = workspaceOutputs //
            # replace git hash in the final binaries
            rustPackageOutputsFinal
            // {
            fedimintd = pickBinary
              {
                pkg = rustPackageOutputsFinal.fedimint-pkgs;
                bin = "fedimintd";
              };
            fedimint-cli = pickBinary
              {
                pkg = rustPackageOutputsFinal.fedimint-pkgs;
                bin = "fedimint-cli";
              };
            distributedgen = pickBinary
              {
                pkg = rustPackageOutputsFinal.fedimint-pkgs;
                bin = "distributedgen";
              };
            gatewayd = pickBinary
              {
                pkg = rustPackageOutputsFinal.gateway-pkgs;
                bin = "gatewayd";
              };
            gateway-cli = pickBinary
              {
                pkg = rustPackageOutputsFinal.gateway-pkgs;
                bin = "gateway-cli";
              };
          };

          # Technically nested sets are not allowed in `packages`, so we can
          # dump the nested things here. They'll work the same way for most
          # purposes (like `nix build`).
          legacyPackages =
            let

              overrideCargoProfileRecursively = deriv: profile: deriv.overrideAttrs (oldAttrs: {
                CARGO_PROFILE = profile;
                cargoArtifacts = if oldAttrs ? "cargoArtifacts" && oldAttrs.cargoArtifacts != null then overrideCargoProfileRecursively oldAttrs.cargoArtifacts profile else null;
              });
            in
            {
              # Debug Builds
              #
              # This works by using `overrideAttrs` on output derivations to set `CARGO_PROFILE`, and importantly
              # recursing into `cargoArtifacts` to do the same. This way a debug build depends on debug build of all dependencies.
              # See https://github.com/ipetkov/crane/discussions/140#discussioncomment-3857137 for more info.
              debug =
                (builtins.mapAttrs (name: deriv: overrideCargoProfileRecursively deriv "dev") workspaceOutputs) //
                (builtins.mapAttrs
                  (name: deriv: replaceGitHash {
                    inherit name; package = overrideCargoProfileRecursively deriv "dev";
                  })
                  rustPackageOutputs) // {
                  cli-test = (builtins.mapAttrs (name: deriv: overrideCargoProfileRecursively deriv "dev") cli-test);
                };

              ci =
                (builtins.mapAttrs (name: deriv: overrideCargoProfileRecursively deriv "ci") workspaceOutputs) //
                (builtins.mapAttrs
                  (name: deriv: replaceGitHash {
                    inherit name; package = overrideCargoProfileRecursively deriv "ci";
                  })
                  rustPackageOutputs) // {
                  cli-test = (builtins.mapAttrs (name: deriv: overrideCargoProfileRecursively deriv "ci") cli-test);
                };

              cross = builtins.mapAttrs
                (name: target: {
                  client-pkgs = (craneBuildCross name).client-pkgs { inherit target; };
                })
                toolchain.crossTargets;


              container =
                let
                  entrypointScript =
                    pkgs.writeShellScriptBin "entrypoint" ''
                      exec bash "${./misc/fedimintd-container-entrypoint.sh}" "$@"
                    '';
                in
                {
                  fedimintd = pkgs.dockerTools.buildLayeredImage {
                    name = "fedimintd";
                    contents = [
                      packages.fedimint-pkgs
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
                        "${builtins.toString 8176}/tcp" = { };
                      };
                    };
                  };

                  fedimint-cli = pkgs.dockerTools.buildLayeredImage {
                    name = "fedimint-cli";
                    contents = [ craneBuildNative.fedimint-pkgs pkgs.bash pkgs.coreutils ];
                    config = {
                      Cmd = [
                        "${craneBuildNative.fedimint-pkgs}/bin/fedimint-cli"
                      ];
                    };
                  };

                  gatewayd = pkgs.dockerTools.buildLayeredImage {
                    name = "gatewayd";
                    contents = [ craneBuildNative.gateway-pkgs pkgs.bash pkgs.coreutils ];
                    config = {
                      Cmd = [
                        "${craneBuildNative.gateway-pkgs}/bin/gatewayd"
                      ];
                    };
                  };
                };
            };


          devShells =

            let
              shellCommon = craneLib:
                let
                  build = craneBuild craneBuild;
                  commonArgs = build.commonArgs;
                  commonEnvs = build.commonEnvs;
                in
                commonEnvs // {
                  buildInputs = commonArgs.buildInputs;
                  nativeBuildInputs = with pkgs; commonArgs.nativeBuildInputs ++ [
                    fenix.packages.${system}.rust-analyzer
                    toolchain.fenixToolchainRustfmt
                    cargo-llvm-cov
                    cargo-udeps
                    pkgs.parallel
                    pkgs.just
                    typos

                    (pkgs.writeShellScriptBin "git-recommit" "exec git commit --edit -F <(cat \"$(git rev-parse --git-path COMMIT_EDITMSG)\" | grep -v -E '^#.*') \"$@\"")

                    # This is required to prevent a mangled bash shell in nix develop
                    # see: https://discourse.nixos.org/t/interactive-bash-with-nix-develop-flake/15486
                    (hiPrio pkgs.bashInteractive)
                    tmux
                    mprocs
                    docker-compose
                    pkgs.tokio-console
                    moreutils-ts

                    # Nix
                    pkgs.nixpkgs-fmt
                    pkgs.shellcheck
                    pkgs.rnix-lsp
                    pkgs.nil
                    pkgs-unstable.convco
                    pkgs.nodePackages.bash-language-server
                  ] ++ lib.optionals (!stdenv.isAarch64 && !stdenv.isDarwin) [
                    pkgs.semgrep
                  ];

                  RUST_SRC_PATH = "${toolchain.fenixChannel.rust-src}/lib/rustlib/src/rust/library";

                  shellHook = ''
                    # auto-install git hooks
                    dot_git="$(git rev-parse --git-common-dir)"
                    if [[ ! -d "$dot_git/hooks" ]]; then mkdir "$dot_git/hooks"; fi
                    for hook in misc/git-hooks/* ; do ln -sf "$(pwd)/$hook" "$dot_git/hooks/" ; done
                    ${pkgs.git}/bin/git config commit.template misc/git-hooks/commit-template.txt

                    # workaround https://github.com/rust-lang/cargo/issues/11020
                    cargo_cmd_bins=( $(ls $HOME/.cargo/bin/cargo-{clippy,udeps,llvm-cov} 2>/dev/null) )
                    if (( ''${#cargo_cmd_bins[@]} != 0 )); then
                      >&2 echo "⚠️  Detected binaries that might conflict with reproducible environment: ''${cargo_cmd_bins[@]}" 1>&2
                      >&2 echo "   Considering deleting them. See https://github.com/rust-lang/cargo/issues/11020 for details" 1>&2
                    fi

                    # Note: the string escaping necessary here (Nix's multi-line string and shell's) is mind-twisting.
                    if [ -n "$TMUX" ]; then
                      # if [ "$(tmux show-options -A default-command)" == 'default-command* \'\''' ]; then
                      if [ "$(tmux show-options -A default-command)" == 'bla' ]; then
                        echo
                        >&2 echo "⚠️  tmux's 'default-command' not set"
                        >&2 echo " ️  Please add 'set -g default-command \"\''${SHELL}\"' to your '$HOME/.tmux.conf' for tmuxinator test setup to work correctly"
                      fi
                    fi

                    # if running in direnv
                    if [ -n "''${DIRENV_IN_ENVRC:-}" ]; then
                      # and not set DIRENV_LOG_FORMAT
                      if [ -n "''${DIRENV_LOG_FORMAT:-}" ]; then
                        >&2 echo "💡 Set 'DIRENV_LOG_FORMAT=\"\"' in your shell environment variables for a cleaner output of direnv"
                      fi
                    fi

                    if [ ''${#TMPDIR} -ge 40 ]; then
                        >&2 echo "⚠️  TMPDIR too long. This might lead to problems running tests and regtest fed. Are you nesting 'nix develop' invocations?"
                    fi

                    if [ "$(ulimit -Sn)" -lt "1024" ]; then
                        >&2 echo "⚠️  ulimit too small. Run 'ulimit -Sn 1024' to avoid problems running tests"
                    fi

                    >&2 echo "💡 Run 'just' for a list of available 'just ...' helper recipes"
                  '';
                };
              shellCommonNative = shellCommon toolchain.craneLibNative;
              shellCommonCross = shellCommon toolchain.craneLibCross;

            in
            {
              # The default shell - meant to developers working on the project,
              # so notably not building any project binaries, but including all
              # the settings and tools necessary to build and work with the codebase.
              default = pkgs.mkShell (shellCommonNative
                // {
                nativeBuildInputs = shellCommonNative.nativeBuildInputs ++ [ toolchain.fenixToolchain ];
              });


              # Shell with extra stuff to support cross-compilation with `cargo build --target <target>`
              #
              # This will pull extra stuff so to save time and download time to most common developers,
              # was moved into another shell.
              cross = pkgs.mkShell (shellCommonCross // {
                nativeBuildInputs = shellCommonCross.nativeBuildInputs ++ [ toolchain.fenixToolchainCrossAll ];

                shellHook = shellCommonCross.shellHook +

                  # Android NDK not available for Arm MacOS
                  (if isArch64Darwin then "" else toolchain.androidCrossEnvVars)
                  + toolchain.wasm32CrossEnvVars;
              });

              # Like `cross` but only with wasm
              crossWasm = pkgs.mkShell (shellCommonCross // {
                nativeBuildInputs = shellCommonCross.nativeBuildInputs ++ [ toolchain.fenixToolchainCrossWasm ];

                shellHook = shellCommonCross.shellHook + toolchain.wasm32CrossEnvVars;
              });

              # this shell is used only in CI, so it should contain minimum amount
              # of stuff to avoid building and caching things we don't need
              lint = pkgs.mkShell {
                nativeBuildInputs = with pkgs; [
                  toolchain.fenixToolchainCargoFmt
                  nixpkgs-fmt
                  shellcheck
                  git
                  parallel
                  semgrep
                  moreutils-ts
                  nix
                ];
              };

              replit = pkgs.mkShell {
                nativeBuildInputs = with pkgs; [
                  pkg-config
                  openssl
                ];
                LIBCLANG_PATH = "${pkgs.libclang.lib}/lib/";
              };

              bootstrap = pkgs.mkShell {
                nativeBuildInputs = with pkgs; [
                  cachix
                ];
              };

              gateway-ui = pkgs.mkShell (shellCommonNative
                // {
                nativeBuildInputs = shellCommonNative.nativeBuildInputs ++ [ pkgs.yarn ];
              });
            };
        in
        {
          inherit packages legacyPackages devShells;

          lib = {
            inherit replaceGitHash devShells;
            commonArgsBase = craneBuildNative.commonArgsBase;
          };


          checks = {
            workspaceBuild = craneBuildNative.workspaceBuild;
            workspaceClippy = craneBuildNative.workspaceClippy;
          };

        });

  nixConfig = {
    extra-substituters = [ "https://fedimint.cachix.org" ];
    extra-trusted-public-keys = [ "fedimint.cachix.org-1:FpJJjy1iPVlvyv4OMiN5y9+/arFLPcnZhZVVCHCDYTs=" ];
  };
}
