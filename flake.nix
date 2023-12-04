{
  inputs = {
    nixpkgs = {
      url = "github:nixpkgs/nixos-23.11";
      # We use nixpkgs as input of `flakebox`, as it locks things like
      # toolchains, in versions that are actually tested in flakebox's CI to
      # cross-compile things well. This also saves us download and Nix
      # evaluation time.
      follows = "flakebox/nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    flakebox = {
      url = "github:rustshop/flakebox?rev=0d2e745bd8ca43ff0cb952debc4bea600e161508";
    };
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, flakebox, advisory-db }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let

          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              (final: prev: {

                esplora-electrs = prev.callPackage ./nix/esplora-electrs.nix {
                  inherit (prev.darwin.apple_sdk.frameworks) Security;
                };

                clightning = prev.clightning.overrideAttrs (oldAttrs: {
                  configureFlags = [ "--enable-developer" "--disable-valgrind" ];
                } // pkgs.lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
                  NIX_CFLAGS_COMPILE = "-Wno-stringop-truncation -w";
                });

                # Note: we are using cargo-nextest from pkgs-unstable because it has some fixes we need
                # Note: shell script adding DYLD_FALLBACK_LIBRARY_PATH because of: https://github.com/nextest-rs/nextest/issues/962
                cargo-nextest = pkgs.writeShellScriptBin "cargo-nextest" "exec env DYLD_FALLBACK_LIBRARY_PATH=\"$(dirname $(${pkgs.which}/bin/which rustc))/../lib\" ${prev.cargo-nextest}/bin/cargo-nextest \"$@\"";

                cargo-llvm-cov = prev.rustPlatform.buildRustPackage rec {
                  pname = "cargo-llvm-cov";
                  version = "0.5.31";
                  buildInputs = [ ];

                  src = pkgs.fetchCrate {
                    inherit pname version;
                    sha256 = "sha256-HjnP9H1t660PJ5eXzgAhrdDEgqdzzb+9Dbk5RGUPjaQ=";
                  };
                  doCheck = false;
                  cargoHash = "sha256-p6zpRRNX4g+jESNSwouWMjZlFhTBFJhe7LirYtFrZ1g=";
                };
              })
            ];
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
                "rust-analysis"
                "rust-src"
                "llvm-tools-preview"
              ];
              # we have our own weird CI workflows
              github.ci.enable = false;
              just.includePaths = [
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

          toolchainsAll = (pkgs.lib.getAttrs
            ([
              "default"
              "nightly"
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
            (flakeboxLib.mkStdFenixToolchains { })
          );
          toolchainsWasm = (pkgs.lib.getAttrs
            [
              "default"
              "wasm32-unknown"
            ]
            (flakeboxLib.mkStdFenixToolchains { })
          );

          toolchainAll = flakeboxLib.mkFenixMultiToolchain {
            toolchains = toolchainsAll;
          };
          toolchainWasm = flakeboxLib.mkFenixMultiToolchain {
            toolchains = toolchainsWasm;
          };

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

            toolchains = toolchainsAll;
            profiles = [ "dev" "ci" "test" "release" ];
          };

          devShells =

            let
              commonShellArgs = craneMultiBuild.commonEnvsShell // craneMultiBuild.commonArgs // {
                buildInputs = craneMultiBuild.commonArgs.buildInputs;
                nativeBuildInputs = craneMultiBuild.commonArgs.nativeBuildInputs ++ [
                  pkgs.cargo-llvm-cov
                  pkgs.cargo-udeps
                  pkgs.cargo-audit
                  pkgs.cargo-deny
                  pkgs.parallel
                  pkgs.just

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
                ] ++ lib.optionals (!stdenv.isAarch64 && !stdenv.isDarwin) [
                  pkgs.semgrep
                ] ++ lib.optionals (stdenv.isLinux) [
                  pkgs.xclip
                  pkgs.wl-clipboard
                ];

                shellHook = ''
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
                '';
              };
            in
            {
              # The default shell - meant to developers working on the project,
              # so notably not building any project binaries, but including all
              # the settings and tools necessary to build and work with the codebase.
              default = flakeboxLib.mkDevShell (commonShellArgs // { });

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
              crossWasm = flakeboxLib.mkDevShell (craneMultiBuild.commonEnvsShell // craneMultiBuild.commonEnvsShellRocksdbLink // {
                toolchain = toolchainWasm;

                packages = [
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
            inherit (craneMultiBuild) gatewayd gateway-cli fedimint-cli fedimintd fedimint-load-test-tool;
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
