{
  inputs = {
    nixpkgs = {
      url = "github:nixos/nixpkgs/nixos-23.11";
    };
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flakebox = {
      url = "github:dpc/flakebox?rev=27ecbf8f2b252dd843d0f58d45658eb56bb5e223";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.fenix.follows = "fenix";
    };
    bundlers = {
      # TODO: switch back to upstream after https://github.com/matthewbauer/nix-bundle/pull/103 is available
      url = "github:dpc/bundlers?branch=24-02-21-tar-deterministic&rev=e8aafe89a11ae0a5f3ce97d1d7d0fcfb354c79eb";
    };
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, flakebox, advisory-db, bundlers, ... }:
    let
      # overlay combining all overlays we use
      overlayAll =
        nixpkgs.lib.composeManyExtensions
          [
            (import ./nix/overlays/rocksdb.nix)
            (import ./nix/overlays/wasm-bindgen.nix)
            (import ./nix/overlays/cargo-nextest.nix)
            (import ./nix/overlays/cargo-llvm-cov.nix)
            (import ./nix/overlays/esplora-electrs.nix)
            (import ./nix/overlays/clightning.nix)
            (import ./nix/overlays/darwin-compile-fixes.nix)
            (import ./nix/overlays/cargo-honggfuzz.nix)
          ];
    in
    {
      overlays = {
        # technically overlay outputs are supposed to be just a function,
        # instead of a list, but keeping this one just to phase it out smoothly
        fedimint = [ overlayAll ];
        all = overlayAll;
        wasm-bindgen = import ./nix/overlays/wasm-bindgen.nix;
        darwin-compile-fixes = import ./nix/overlays/darwin-compile-fixes.nix;
        cargo-honggfuzz = import ./nix/overlays/cargo-honggfuzz.nix;
      };

      bundlers = bundlers.bundlers;
      defaultBundler = bundlers.defaultBundler;
    } //
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ overlayAll ];
          };

          lib = pkgs.lib;

          stdenv = pkgs.stdenv;

          flakeboxLib = flakebox.lib.${system} {
            # customizations will go here in the future
            config = {
              toolchain.components = [
                "rustc"
                "cargo"
                "clippy"
                "rust-analyzer"
                "rust-src"
                "llvm-tools"
              ];

              motd = {
                enable = true;
                command = ''
                  >&2 echo "🚧 In an enfort to improve documentation, we now require all structs and"
                  >&2 echo "🚧 and public methods to be documented with a docstring."
                  >&2 echo "🚧 See https://github.com/fedimint/fedimint/issues/3807"
                '';
              };
              # we have our own weird CI workflows
              github.ci.enable = false;
              just.importPaths = [
                "justfile.fedimint.just"
              ];
              # we have a custom final check
              just.rules.final-check.enable = false;
              git.pre-commit.trailing_newline = false;
              git.pre-commit.hooks = {
                check_forbidden_dependencies = builtins.readFile ./nix/check-forbidden-deps.sh;
              };
            };
          };

          toolchainArgs = {
            extraRustFlags = "--cfg tokio_unstable";
          } // lib.optionalAttrs pkgs.stdenv.isDarwin {
            # on Darwin newest stdenv doesn't seem to work
            # linking rocksdb
            stdenv = pkgs.clang11Stdenv;
          };

          stdTargets = flakeboxLib.mkStdTargets { };
          stdToolchains = flakeboxLib.mkStdToolchains toolchainArgs;


          # toolchains for the native build (default shell)
          toolchainNative = flakeboxLib.mkFenixToolchain (toolchainArgs
          // {
            targets = (pkgs.lib.getAttrs
              [
                "default"
                "wasm32-unknown"
              ]
              stdTargets
            );
          });

          # toolchains for the native + wasm build
          toolchainWasm = flakeboxLib.mkFenixToolchain (toolchainArgs
          // {
            defaultTarget = "wasm32-unknown-unknown";
            targets = (pkgs.lib.getAttrs
              [
                "default"
                "wasm32-unknown"
              ]
              stdTargets
            );

            args = {
              nativeBuildInputs = [ pkgs.firefox pkgs.wasm-bindgen-cli pkgs.geckodriver pkgs.wasm-pack ];
            };
          });

          # toolchains for the native + wasm build
          toolchainAll = flakeboxLib.mkFenixToolchain (toolchainArgs
          // {
            targets = (pkgs.lib.getAttrs
              ([
                "default"
                "aarch64-android"
                "x86_64-android"
                "arm-android"
                "armv7-android"
                "wasm32-unknown"
              ] ++ lib.optionals pkgs.stdenv.isDarwin [
                "aarch64-ios"
                "aarch64-ios-sim"
                "x86_64-ios"
              ])
              stdTargets);
          });
          # Replace placeholder git hash in a binary
          #
          # To avoid impurity, we use a git hash placeholder when building binaries
          # and then replace them with the real git hash in the binaries themselves.
          replaceGitHash =
            let
              # the hash we will set if the tree is dirty;
              dirtyHashPrefix = builtins.substring 0 16 self.dirtyRev;
              dirtyHashSuffix = builtins.substring (40 - 16) 16 self.dirtyRev;
              # the string needs to be 40 characters, like the original,
              # so to denote `-dirty` we replace the middle with zeros
              dirtyHash = "${dirtyHashPrefix}00000000${dirtyHashSuffix}";
            in
            { package, name, placeholder, gitHash ? if (self ? rev) then self.rev else dirtyHash }:
            stdenv.mkDerivation {
              inherit system;
              inherit name;

              dontUnpack = true;
              dontStrip = !pkgs.stdenv.isDarwin;

              installPhase = ''
                cp -a ${package} $out
                for path in `find $out -type f -executable`; do
                  # need to use a temporary file not to overwrite source as we are reading it
                  bbe -e 's/${placeholder}/${gitHash}/' $path -o ./tmp || exit 1
                  chmod +w $path
                  # use cat to keep all the original permissions etc as they were
                  cat ./tmp > "$path"
                  chmod -w $path
                done
              '';

              buildInputs = [ pkgs.bbe ];
            };


          craneMultiBuild = import nix/flakebox.nix {
            inherit pkgs flakeboxLib advisory-db replaceGitHash;

            # Yes, you're seeing right. We're passing result of this call as an argument
            # to it.
            inherit craneMultiBuild;

            toolchains = stdToolchains // { "wasm32-unknown" = toolchainWasm; };
            profiles = [ "dev" "ci" "test" "release" ];
          };

          devShells =

            let
              commonShellArgs = craneMultiBuild.commonEnvsShell // craneMultiBuild.commonArgs // {
                toolchain = toolchainNative;
                buildInputs = craneMultiBuild.commonArgs.buildInputs;
                nativeBuildInputs = craneMultiBuild.commonArgs.nativeBuildInputs ++ [
                  pkgs.cargo-llvm-cov
                  pkgs.cargo-udeps
                  pkgs.cargo-audit
                  pkgs.cargo-deny
                  pkgs.parallel
                  pkgs.just
                  pkgs.time
                  pkgs.gawk

                  (pkgs.writeShellScriptBin "git-recommit" "exec git commit --edit -F <(cat \"$(git rev-parse --git-path COMMIT_EDITMSG)\" | grep -v -E '^#.*') \"$@\"")

                  # This is required to prevent a mangled bash shell in nix develop
                  # see: https://discourse.nixos.org/t/interactive-bash-with-nix-develop-flake/15486
                  (pkgs.hiPrio pkgs.bashInteractive)
                  pkgs.tmux
                  pkgs.tmuxinator
                  (pkgs.mprocs.overrideAttrs (final: prev: {
                    patches = prev.patches ++ [
                      (pkgs.fetchurl {
                        url = "https://github.com/pvolok/mprocs/pull/88.patch";
                        name = "clipboard-fix.patch";
                        sha256 = "sha256-9dx1vaEQ6kD66M+vsJLIq1FK+nEObuXSi3cmpSZuQWk=";
                      })
                    ];
                  }))
                  pkgs.docker-compose
                  pkgs.tokio-console
                  pkgs.git

                  # Nix
                  pkgs.nixpkgs-fmt
                  pkgs.shellcheck
                  pkgs.rnix-lsp
                  pkgs.nil
                  pkgs.convco
                  pkgs.nodePackages.bash-language-server
                  pkgs.sccache
                ] ++ lib.optionals (!stdenv.isAarch64 && !stdenv.isDarwin) [
                  pkgs.semgrep
                ];

                shellHook = ''
                  root="$(git rev-parse --show-toplevel)"

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

                  if [ ''${#TMPDIR} -ge 40 ]; then
                      >&2 echo "⚠️  TMPDIR too long. This might lead to problems running tests and regtest fed. Are you nesting 'nix develop' invocations?"
                  fi

                  if [ "$(ulimit -Sn)" -lt "1024" ]; then
                      >&2 echo "⚠️  ulimit too small. Run 'ulimit -Sn 1024' to avoid problems running tests"
                  fi

                  if [ -z "$(git config --global merge.ours.driver)" ]; then
                      >&2 echo "⚠️  Recommended to run 'git config --global merge.ours.driver true' to enable better lock file handling. See https://blog.aspect.dev/easier-merges-on-lockfiles for more info"
                  fi

                  export RUSTC_WRAPPER=${pkgs.sccache}/bin/sccache
                  export CARGO_BUILD_TARGET_DIR="''${CARGO_BUILD_TARGET_DIR:-''${root}/target-nix}"
                  export FM_DISCOVER_API_VERSION_TIMEOUT=10
                '';
              };
            in
            {
              # The default shell - meant to developers working on the project,
              # so notably not building any project binaries, but including all
              # the settings and tools necessary to build and work with the codebase.
              default = flakeboxLib.mkDevShell (commonShellArgs // { });

              fuzz = flakeboxLib.mkDevShell (commonShellArgs // {
                nativeBuildInputs = with pkgs; [
                  cargo-hongfuzz
                  libbfd_2_38
                  libunwind.dev
                  libopcodes_2_38
                  libblocksruntime
                  lldb
                ];
              });

              lint = flakeboxLib.mkLintShell { };

              # Shell with extra stuff to support cross-compilation with `cargo build --target <target>`
              #
              # This will pull extra stuff so to save time and download time to most common developers,
              # was moved into another shell.
              cross = flakeboxLib.mkDevShell (commonShellArgs // craneMultiBuild.commonEnvsShellRocksdbLinkCross // {
                toolchain = toolchainAll;
                shellHook = ''
                  # hijack cargo for our evil purposes
                  export CARGO_ORIG_BIN="$(${pkgs.which}/bin/which cargo)"
                  git_root="$(git rev-parse --show-toplevel)"
                  export PATH="''${git_root}/nix/cargo-wrapper/:$PATH"
                '';
              });

              # Like `cross` but only with wasm
              crossWasm = flakeboxLib.mkDevShell (commonShellArgs // {
                toolchain = toolchainWasm;

                nativeBuildInputs = commonShellArgs.nativeBuildInputs or [ ] ++ [
                  pkgs.wasm-pack
                  pkgs.wasm-bindgen-cli
                  pkgs.geckodriver
                ] ++ lib.optionals (stdenv.isLinux) [
                  pkgs.firefox
                ];
              });

              replit = pkgs.mkShell {
                nativeBuildInputs = with pkgs; [
                  pkg-config
                  openssl
                ];
              };

              bootstrap = pkgs.mkShell {
                nativeBuildInputs = with pkgs; [
                  cachix
                ];
              };
            };
        in
        {
          inherit devShells;

          # Technically nested sets are not allowed in `packages`, so we can
          # dump the nested things here. They'll work the same way for most
          # purposes (like `nix build`).
          legacyPackages = craneMultiBuild;

          packages = {
            inherit (craneMultiBuild) gatewayd fedimint-dbtool gateway-cli fedimint-cli fedimintd fedimint-load-test-tool;
            inherit (craneMultiBuild) client-pkgs gateway-pkgs fedimint-pkgs devimint;
          };

          lib = {
            inherit replaceGitHash devShells;
          };
        });

  nixConfig = {
    extra-substituters = [ "https://fedimint.cachix.org" ];
    extra-trusted-public-keys = [ "fedimint.cachix.org-1:FpJJjy1iPVlvyv4OMiN5y9+/arFLPcnZhZVVCHCDYTs=" ];
  };
}
