#!/usr/bin/env bash
set -eou pipefail

# check the things involving cargo
# We're using Nix + crane + flakebox,
# this gives us caching between different
# builds and decent isolation.
function job_cargo() {
    selfci step start "cargo.lock up to date"
    if ! cargo update --workspace --locked -q; then
      selfci step fail
    fi

    # there's not point continuing if we can't build
    selfci step start "build"
    nix build -L .#ci.workspaceBuild

    selfci step start "clippy"
    if ! nix build -L .#ci.workspaceClippy ; then
      selfci step fail
    fi

    selfci step start "tests"
    if ! nix build -L .#ci.ciTestAll ; then
      selfci step fail
    fi
}

case "$SELFCI_JOB_NAME" in
  main)
    selfci job start "cargo"
    selfci job start "lint"

    selfci job wait "lint"
    selfci job wait "cargo"

    selfci job start "cargo-udeps"
    ;;

  cargo)
    job_cargo
    ;;

  lint)
    nix develop --ignore-environment .#lint --command ./misc/git-hooks/pre-commit
    ;;

  cargo-udeps)
    nix build -L .#nightly.test.workspaceCargoUdeps
    ;;

  check-flake)
    nix flake show .#
    ;;

  *)
    echo "Unknown job: $SELFCI_JOB_NAME"
    exit 1
esac
