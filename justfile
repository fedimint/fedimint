default:
  @just --list

# run `cargo build` on everything
build:
  cargo build --workspace --all-targets

# run `cargo check` on everything
check:
  cargo check --workspace --all-targets

# run `cargo clippy` on everything
clippy:
  cargo clippy --workspace --all-targets -- --deny warnings --allow deprecated

# run `cargo clippy --fix` on everything
clippy-fix:
  cargo clippy --workspace --all-targets --fix

# check if ulimit is set correctly
check-ulimit:
  #!/usr/bin/env bash
  if [ "$(ulimit -Sn)" -lt "1024" ]; then
      >&2 echo "⚠️  ulimit too small. Run 'ulimit -Sn 1024' to avoid problems running tests"
  fi

# run tests
test: build check-ulimit
  cargo test

# run tests against real services (like bitcoind)
test-real: check-ulimit
  ./scripts/tests/rust-tests.sh

# run all tests in parallel like CI would
test-ci-all:
  ./scripts/tests/test-ci-all.sh

# show number of tests per package
test-count:
  ./scripts/tests/test-cov.sh

# run lints (quick)
lint:
  env NO_STASH=true misc/git-hooks/pre-commit
  just clippy
  env RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links -D warnings' cargo doc --profile dev --no-deps --document-private-items

# fix some lint failures
lint-fix:
  just format
  just clippy-fix

# `cargo udeps` check
udeps:
  nix build -L .#debug.workspaceCargoUdeps

# run all checks recommended before opening a PR
final-check: lint
  cargo test --doc
  just check-wasm
  just test

check-wasm:
  nix develop .#crossWasm -c cargo check --target wasm32-unknown-unknown --package fedimint-client

[no-exit-message]
typos:
  #!/usr/bin/env bash
  set -eo pipefail

  git_ls_files="$(git ls-files)"
  git_ls_nonbinary_files="$(echo "$git_ls_files" |  grep -v -E "^db/|\.png\$|\.ods\$")"

  if ! echo "$git_ls_nonbinary_files" | typos --stdin-paths ; then
    >&2 echo "Typos found: Valid new words can be added to '_typos.toml'"
    return 1
  fi


[no-exit-message]
typos-fix-all:
  #!/usr/bin/env bash
  set -eo pipefail

  git_ls_files="$(git ls-files)"
  git_ls_nonbinary_files="$(echo "$git_ls_files" | xargs file --mime | grep -v "; charset=binary" | cut -d: -f1)"

  if ! echo "$git_ls_nonbinary_files" | typos --stdin-paths -w  ; then
    >&2 echo "Typos found: Valid new words can be added to '_typos.toml'"
    # TODO: not enforcing anything right, just being annoying in the CLI
    # return 1
  fi

# regenerate migration snapshots
prepare_db_migration_snapshots +extra_args:
  env FM_PREPARE_DB_MIGRATION_SNAPSHOTS=1 cargo test ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} prepare_db_migration_snapshots -- {{extra_args}}

# run code formatters
format:
  cargo fmt --all
  nixpkgs-fmt $(echo **.nix)

# start mprocs with a dev federation setup
mprocs:
  ./scripts/dev/mprocs/run.sh

# exit mprocs session
exit-mprocs:
  mprocs --ctl '{c: quit}' --server 127.0.0.1:4050

# start tmuxinator with dev federation setup
tmuxinator:
  ./scripts/dev/tmuxinator/run.sh

# exit tmuxinator session
exit-tmuxinator:
  tmux kill-session -t fedimint-dev
