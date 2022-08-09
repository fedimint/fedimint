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

        fenix-pkgs = fenix.packages.${system};
        fenix-channel = fenix-pkgs.stable;

        craneLib = (crane.mkLib pkgs).overrideScope' (final: prev: {
          cargo = fenix-channel.cargo;
          rustc = fenix-channel.rustc;
        });

        commonArgs = {
          src = ./.;

          buildInputs = with pkgs; [
            openssl
            pkg-config
            perl
            fenix-channel.rustc
          ];

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];
        };

        minimintDeps = craneLib.buildDepsOnly (commonArgs // {
          pname = "minimint-dependencies";
        });

        minimintClippy = craneLib.cargoClippy (commonArgs // {
          cargoArtifacts = minimintDeps;
          cargoClippyExtraArgs = "-- --deny warnings";
        });

        minimint = craneLib.buildPackage (commonArgs // {
          cargoArtifacts = minimintDeps;
        });

        minimintCoverage = craneLib.cargoTarpaulin (commonArgs // {
          cargoArtifacts = minimintDeps;
        });
      in
      {
        packages = {
          default = minimint;
          deps = minimintDeps;
        };

        checks = {
          inherit
            minimint
            minimintClippy
            minimintCoverage;
        };

        devShell =
          let
            clightning-dev = pkgs.clightning.overrideAttrs (oldAttrs: {
              configureFlags = [ "--enable-developer" "--disable-valgrind" ];
            } // pkgs.lib.optionalAttrs (!pkgs.stdenv.isDarwin) {
              NIX_CFLAGS_COMPILE = "-Wno-stringop-truncation";
            });
            bitcoind-patch-darwin = pkgs.bitcoind.overrideAttrs (oldAttrs: {
              doCheck = !(pkgs.stdenv.isDarwin && pkgs.stdenv.isAarch64);
            });
          in

          pkgs.mkShell {
            buildInputs = minimintDeps.buildInputs;
            nativeBuildInputs = with pkgs; minimintDeps.nativeBuildInputs ++ [
              fenix-pkgs.rust-analyzer
              fenix-channel.rustfmt
              fenix-channel.rustc
              fenix-channel.cargo

              bc
              perl
              bitcoind-patch-darwin
              clightning-dev
              jq
              procps
              tmux
              tmuxinator

              # Nix
              pkgs.nixpkgs-fmt
              pkgs.shellcheck
              pkgs.rnix-lsp
              pkgs.nodePackages.bash-language-server
            ] ++ lib.optionals stdenv.isDarwin [
              libiconv
              darwin.apple_sdk.frameworks.Security
            ];
            RUST_SRC_PATH = "${fenix-channel.rust-src}/lib/rustlib/src/rust/library";

            shellHook = ''
              # auto-install git hooks
              for hook in misc/git-hooks/* ; do ln -sf "../../$hook" "./.git/hooks/" ; done
              ${pkgs.git}/bin/git config commit.template misc/git-hooks/commit-template.txt
            '';
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
      });
}
