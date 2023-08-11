{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.05";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixpkgs-kitman.url = "github:jkitman/nixpkgs/add-esplora-pkg";
    crane.url = "github:ipetkov/crane?rev=6c25eff4edca8556df21f55c63e49f20efe4be95";
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
    android-nixpkgs = {
      # url = "github:tadfisher/android-nixpkgs?rev=39538bf26d9064555c2a77b5bd6eb88049285905"; # stable
      url = "github:dpc/android-nixpkgs?rev=ffce46832f161877b7c197bfc7def734e8b9caa4"; # stable channel + workaround https://github.com/tadfisher/android-nixpkgs/issues/59
    };
  };

  outputs = { self, nixpkgs, nixpkgs-unstable, nixpkgs-kitman, flake-utils, flake-compat, fenix, crane, advisory-db, android-nixpkgs }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };

          pkgs-unstable = import nixpkgs-unstable {
            inherit system;
          };

          pkgs-kitman = import nixpkgs-kitman {
            inherit system;
          };

          lib = pkgs.lib;

          stdenv = pkgs.stdenv;

          clightning-dev = pkgs.clightning.overrideAttrs (oldAttrs: {
            configureFlags = [ "--enable-developer" "--disable-valgrind" ];
          } // pkgs.lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
            NIX_CFLAGS_COMPILE = "-Wno-stringop-truncation -w";
          });

          # `moreutils/bin/parallel` and `parallel/bin/parallel` conflict, so just use
          # the binary we need from `moreutils`
          moreutils-ts = pkgs.writeShellScriptBin "ts" "exec ${pkgs.moreutils}/bin/ts \"$@\"";

          toolchain = import ./flake.toolchain.nix {
            inherit pkgs lib system stdenv fenix android-nixpkgs;
          };

          craneLib' = crane.lib.${system};
          craneLibNative' = craneLib'.overrideToolchain toolchain.fenixToolchain;

          craneLibCross' = builtins.mapAttrs
            (name: target: crane.lib.${system}.overrideToolchain toolchain.fenixToolchainCross.${name})
            toolchain.crossTargets
          ;
          craneExtendCommon = import ./nix/craneCommon.nix
            {
              inherit pkgs pkgs-kitman clightning-dev advisory-db lib moreutils-ts;

              src = ./.;
              srcDotCargo = ./.cargo;
            };

          craneExtendBuild = import ./nix/craneBuild.nix
            {
              inherit pkgs pkgs-kitman clightning-dev advisory-db lib moreutils-ts;
            };

          craneLibNative = craneExtendBuild (craneExtendCommon craneLibNative');
          craneLibDevShell = craneLibNative.overrideScope' (self: prev: {
            commonProfile = null;
          });
          craneLibCross = target: craneExtendBuild (craneExtendCommon craneLibCross'.${target});

          # Replace placeholder git hash in a binary
          #
          # To avoid impurity, we use a git hash placeholder when building binaries
          # and then replace them with the real git hash in the binaries themselves.
          replaceGitHash = { package, name, placeholder }:
            let
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
                  bbe -e 's/${placeholder}/${git-hash}/' $path -o ./tmp || exit 1
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
          # For efficiency we built some binaries together (like fedimintd + fedimint-cli),
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
          workspaceOutputs = craneLib: {
            workspaceDeps = craneLib.workspaceDeps;
            workspaceBuild = craneLib.workspaceBuild;
            workspaceClippy = craneLib.workspaceClippy;
            workspaceTest = craneLib.workspaceTest;
            workspaceTestDoc = craneLib.workspaceTestDoc;
            workspaceDoc = craneLib.workspaceDoc;
            workspaceDocExport = (craneLib.overrideToolchain toolchain.fenixToolchainDocNightly).workspaceDocExport;
            workspaceCargoUdeps = ((craneLib.overrideScope' (self: prev: {
              # udeps works only with `test` profile
              commonProfile = "test";
            })).overrideToolchain toolchain.fenixToolchainDocNightly).workspaceCargoUdeps;
            workspaceCov = craneLib.workspaceCov;
            workspaceAudit = craneLib.workspaceAudit;
          };

          # Outputs that build a particular Rust package.
          # Notably, these don't have the git hash replaced (yet) - for that, see `rustPackageOutputsFinal`
          rustPackageOutputs = craneLib: {
            default = craneLib.fedimint-pkgs;

            fedimint-pkgs = craneLib.fedimint-pkgs;
            gateway-pkgs = craneLib.gateway-pkgs;
            client-pkgs = craneLib.client-pkgs { };
            devimint = craneLib.devimint;
            fedimint-load-test-tool = craneLib.fedimint-load-test-tool;
          };

          # `rustPackageOutputs` with git hash replaced from placeholder to a real value
          # To avoid rebuilding too much source needlessly, we replace placeholders with real git hash (which changes on every build),
          # as a very last step.
          rustPackageOutputsFinal = craneLib: builtins.mapAttrs (name: package: replaceGitHash { inherit name package; placeholder = craneLib.gitHashPlaceholderValue; }) (rustPackageOutputs craneLib);

          # All tests, grouped together, so we can `nix build -L .#cli-test.<name>` or `nix build -L .#ci.cli-test.<name>`, etc.
          cli-test = craneLib: {
            all = craneLib.cliTestsAll;
            reconnect = craneLib.cliTestReconnect;
            latency = craneLib.cliTestLatency;
            cli = craneLib.cliTestCli;
            load-test-tool = craneLib.cliLoadTestToolTest;
            rust-tests = craneLib.cliRustTests;
            always-fail = craneLib.cliTestAlwaysFail;
          };

          wasm-tests = { craneLibNative, craneLibCross }: craneLibCross.wasmTests {
            nativeWorkspaceBuild = craneLibNative.workspaceBuild;
            wasmTarget = toolchain.crossTargets.wasm32-unknown-unknown;
          };

          # packages we expose from our flake (note: we also expose `legacyPackages` for hierarchical outputs)
          packages = craneLib: (workspaceOutputs craneLib) //
            # replace git hash in the final binaries
            (rustPackageOutputsFinal craneLib)
            // {
            fedimintd = pickBinary
              {
                pkg = (rustPackageOutputsFinal craneLib).fedimint-pkgs;
                bin = "fedimintd";
              };
            fedimint-cli = pickBinary
              {
                pkg = (rustPackageOutputsFinal craneLib).fedimint-pkgs;
                bin = "fedimint-cli";
              };
            fedimint-dbtool = pickBinary
              {
                pkg = (rustPackageOutputsFinal craneLib).fedimint-pkgs;
                bin = "fedimint-dbtool";
              };
            gatewayd = pickBinary
              {
                pkg = (rustPackageOutputsFinal craneLib).gateway-pkgs;
                bin = "gatewayd";
              };
            gateway-cli = pickBinary
              {
                pkg = (rustPackageOutputsFinal craneLib).gateway-pkgs;
                bin = "gateway-cli";
              };
            fedimint-load-test-tool = pickBinary
              {
                pkg = (rustPackageOutputsFinal craneLib).fedimint-load-test-tool;
                bin = "fedimint-load-test-tool";
              };
          };

          # Technically nested sets are not allowed in `packages`, so we can
          # dump the nested things here. They'll work the same way for most
          # purposes (like `nix build`).
          legacyPackages =
            let
              craneLibDebug = craneLibNative.overrideScope' (self: prev: {
                commonProfile = "dev";
              });
              craneLibCi = craneLibNative.overrideScope' (self: prev: {
                commonProfile = "ci";
              });
            in
            {
              # Debug Builds
              #
              # This works by using `overrideAttrs` on output derivations to set `CARGO_PROFILE`, and importantly
              # recursing into `cargoArtifacts` to do the same. This way a debug build depends on debug build of all dependencies.
              # See https://github.com/ipetkov/crane/discussions/140#discussioncomment-3857137 for more info.
              debug = (workspaceOutputs craneLibDebug) // { cli-test = cli-test craneLibDebug; } // (packages craneLibDebug);

              ci = (workspaceOutputs craneLibCi) // {
                wasm-tests = wasm-tests {
                  craneLibCross = (craneLibCross "wasm32-unknown-unknown").overrideScope' (self: prev: {
                    commonProfile = "ci";
                  });
                  craneLibNative = craneLibCi;
                };
                cli-test = cli-test craneLibCi;
              } // (packages craneLibCi);

              cross = builtins.mapAttrs
                (name: target: {
                  client-pkgs = (craneLibCross name).client-pkgs { inherit target; };
                })
                toolchain.crossTargets;


              container =
                let
                  entrypointScript =
                    pkgs.writeShellScriptBin "entrypoint" ''
                      exec bash "${./misc/fedimintd-container-entrypoint.sh}" "$@"
                    '';
                  packagesNative = (packages craneLibNative);
                in
                {
                  fedimintd = pkgs.dockerTools.buildLayeredImage {
                    name = "fedimintd";
                    contents = [
                      packagesNative.fedimint-pkgs
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
                    contents = [ craneLibNative.fedimint-pkgs pkgs.bash pkgs.coreutils ];
                    config = {
                      Cmd = [
                        "${craneLibNative.fedimint-pkgs}/bin/fedimint-cli"
                      ];
                    };
                  };

                  gatewayd = pkgs.dockerTools.buildLayeredImage {
                    name = "gatewayd";
                    contents = [ craneLibNative.gateway-pkgs pkgs.bash pkgs.coreutils ];
                    config = {
                      Cmd = [
                        "${craneLibNative.gateway-pkgs}/bin/gatewayd"
                      ];
                    };
                  };

                  gateway-cli = pkgs.dockerTools.buildLayeredImage {
                    name = "gateway-cli";
                    contents = [ craneLibNative.gateway-pkgs pkgs.bash pkgs.coreutils ];
                    config = {
                      Cmd = [
                        "${craneLibNative.gateway-pkgs}/bin/gateway-cli"
                      ];
                    };
                  };
                };
            };

          devShells =

            let
              shellCommon = craneLib:
                let
                  build = craneLibDevShell;
                  commonArgs = build.commonArgs;
                  commonEnvsShell = build.commonEnvsShell;
                in
                commonEnvsShell // {
                  buildInputs = commonArgs.buildInputs;
                  nativeBuildInputs = with pkgs; commonArgs.nativeBuildInputs ++ [
                    pkgs.rust-analyzer
                    toolchain.fenixToolchainRustfmt
                    cargo-llvm-cov
                    pkgs-unstable.cargo-udeps
                    pkgs.parallel
                    pkgs.just
                    typos

                    (pkgs.writeShellScriptBin "git-recommit" "exec git commit --edit -F <(cat \"$(git rev-parse --git-path COMMIT_EDITMSG)\" | grep -v -E '^#.*') \"$@\"")

                    # This is required to prevent a mangled bash shell in nix develop
                    # see: https://discourse.nixos.org/t/interactive-bash-with-nix-develop-flake/15486
                    (hiPrio pkgs.bashInteractive)
                    tmux
                    tmuxinator
                    (mprocs.overrideAttrs (final: prev: {
                      patches = prev.patches ++ [
                        (fetchurl {
                          url = "https://github.com/pvolok/mprocs/pull/88.patch";
                          name = "clipboard-fix.patch";
                          sha256 = "sha256-9dx1vaEQ6kD66M+vsJLIq1FK+nEObuXSi3cmpSZuQWk=";
                        })
                      ];
                    }))
                    docker-compose
                    pkgs.tokio-console
                    pkgs.git
                    moreutils-ts

                    # Nix
                    pkgs.nixpkgs-fmt
                    pkgs.shellcheck
                    pkgs.rnix-lsp
                    pkgs.nil
                    pkgs.convco
                    pkgs.nodePackages.bash-language-server
                  ] ++ lib.optionals (!stdenv.isAarch64 && !stdenv.isDarwin) [
                    pkgs.semgrep
                  ] ++ lib.optionals (stdenv.isLinux) [
                    xclip
                    wl-clipboard
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

              nightly = pkgs.mkShell (shellCommonNative
                // {
                nativeBuildInputs = shellCommonNative.nativeBuildInputs ++ [ toolchain.fenixToolchainNightly pkgs.cargo-fuzz ];
              });

              # Shell with extra stuff to support cross-compilation with `cargo build --target <target>`
              #
              # This will pull extra stuff so to save time and download time to most common developers,
              # was moved into another shell.
              cross = pkgs.mkShell (shellCommonCross // {
                nativeBuildInputs = shellCommonCross.nativeBuildInputs ++ [ toolchain.fenixToolchainCrossAll ];

                shellHook = shellCommonCross.shellHook
                  + toolchain.androidCrossEnvVars
                  + toolchain.wasm32CrossEnvVars;
              });

              # Like `cross` but only with wasm
              crossWasm = pkgs.mkShell (shellCommonCross // {
                nativeBuildInputs = shellCommonCross.nativeBuildInputs ++ [
                  toolchain.fenixToolchainCrossWasm
                  pkgs.wasm-pack
                  pkgs.wasm-bindgen-cli
                  pkgs.geckodriver
                ] ++ lib.optionals (stdenv.isLinux) [
                  pkgs.firefox
                ];

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
                  typos
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
            };
        in
        {
          inherit devShells legacyPackages;

          packages = packages craneLibNative;

          lib = {
            inherit replaceGitHash devShells;
            commonArgsBase = craneLibNative.commonArgsBase;
          };

          checks = {
            workspaceBuild = craneLibNative.workspaceBuild;
            workspaceClippy = craneLibNative.workspaceClippy;
          };

        });

  nixConfig = {
    extra-substituters = [ "https://fedimint.cachix.org" ];
    extra-trusted-public-keys = [ "fedimint.cachix.org-1:FpJJjy1iPVlvyv4OMiN5y9+/arFLPcnZhZVVCHCDYTs=" ];
  };
}
