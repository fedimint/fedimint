#!/usr/bin/env bash
set -eou pipefail

function should_skip_step() {
    local env_var_name="$1"
    [[ "${!env_var_name:-false}" == "true" ]]
}

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
    if should_skip_step FM_SELFCI_CHECK_SKIP_BUILD; then
      echo "Skipping build because FM_SELFCI_CHECK_SKIP_BUILD=true"
    else
      selfci step start "build"
      nix build -L .#ci.workspaceBuild
    fi

    if should_skip_step FM_SELFCI_CHECK_SKIP_CLIPPY; then
      echo "Skipping clippy because FM_SELFCI_CHECK_SKIP_CLIPPY=true"
    else
      selfci step start "clippy"
      if ! nix build -L .#ci.workspaceClippy ; then
        selfci step fail
      fi
    fi

    if should_skip_step FM_SELFCI_CHECK_SKIP_TESTS; then
      echo "Skipping tests because FM_SELFCI_CHECK_SKIP_TESTS=true"
    else
      selfci step start "tests"
      if ! nix build -L .#ci.ciTestAll ; then
        selfci step fail
      fi
    fi
}

case "$SELFCI_JOB_NAME" in
  main)
    selfci job start "cargo"
    selfci job start "lint"

    selfci job wait "lint"
    selfci job wait "cargo"

    selfci job start "cargo-crap"
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

  cargo-crap)
    selfci step start "cargo-crap"
    if ! nix build -L .#ci.crap ; then
      >&2 echo "cargo-crap: failed - CRAP-score regression above 1000 detected"
      selfci step fail
    fi
    ;;

  check-flake)
    nix flake show .#
    ;;

  *)
    echo "Unknown job: $SELFCI_JOB_NAME"
    exit 1
esac
