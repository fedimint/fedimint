# workaround: https://github.com/casey/just/issues/1669
[private]
default-fedi:
  just default

# check if ulimit is set correctly
check-ulimit:
  #!/usr/bin/env bash
  if [ "$(ulimit -Sn)" -lt "1024" ]; then
      >&2 echo "⚠️  ulimit too small. Run 'ulimit -Sn 1024' to avoid problems running tests"
  fi

# run tests against real services (like bitcoind)
test-real: check-ulimit
  ./scripts/tests/rust-tests.sh

# run all tests in parallel like CI would
test-ci-all:
  ./scripts/tests/test-ci-all.sh

# show number of tests per package
test-count:
  ./scripts/tests/test-cov.sh

# `cargo udeps` check
udeps:
  nix build -L .#debug.workspaceCargoUdeps

# run all checks recommended before opening a PR
final-check: lint
  # can't use nextest due to: https://github.com/nextest-rs/nextest/issues/16
  cargo test --doc
  just check-wasm
  just test

check-wasm:
  nix develop .#crossWasm -c cargo check --target wasm32-unknown-unknown --package fedimint-client

# regenerate migration snapshots
# ex: `just prepare_db_migration_snapshots fedimint-server`
# ex: `just prepare_db_migration_snapshots fedimint-mint-server`
# ex: `just prepare_db_migration_snapshots fedimint-ln-server`
# ex: `just prepare_db_migration_snapshots fedimint-wallet-server`
prepare_db_migration_snapshots +extra_args:
  env FM_PREPARE_DB_MIGRATION_SNAPSHOTS=force cargo test ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -p {{extra_args}} prepare_db_migration_snapshots

# start mprocs with a dev federation setup. Default: 4 nodes, add `-n 1` argument to start only 1 node
mprocs *PARAMS:
  ./scripts/dev/mprocs/run.sh {{PARAMS}}

# exit mprocs session
exit-mprocs:
  mprocs --ctl '{c: quit}' --server 127.0.0.1:4050

# start tmuxinator with dev federation setup
tmuxinator:
  ./scripts/dev/tmuxinator/run.sh

# exit tmuxinator session
exit-tmuxinator:
  tmux kill-session -t fedimint-dev

# backport a PR
backport-pr pr:
  nix shell nixpkgs#nodejs -c npx backport --pr-filter {{pr}}
