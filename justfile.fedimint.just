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

test-compatibility *VERSIONS:
  ./scripts/tests/test-ci-all-backcompat.sh {{VERSIONS}}

test-full-compatibility *VERSIONS:
  env FM_FULL_VERSION_MATRIX=1 ./scripts/tests/test-ci-all-backcompat.sh {{VERSIONS}}

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

# regenerate server db migration snapshots
# ex: `just snapshot-server-db-migrations fedimint-server`
# ex: `just snapshot-server-db-migrations fedimint-mint-tests`
# ex: `just snapshot-server-db-migrations fedimint-ln-tests`
# ex: `just snapshot-server-db-migrations fedimint-wallet-tests`
# ex: `just snapshot-server-db-migrations fedimint-dummy-tests`
# ex: `just snapshot-server-db-migrations fedimint-ln-gateway`
snapshot-server-db-migrations PACKAGE *EXTRA_ARGS:
  env FM_PREPARE_DB_MIGRATION_SNAPSHOTS=force cargo nextest run --workspace --all-targets ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -E 'package({{PACKAGE}})' snapshot_server_db_migrations {{EXTRA_ARGS}}
  just test-server-db-migrations {{PACKAGE}} {{EXTRA_ARGS}}

test-server-db-migrations PACKAGE *EXTRA_ARGS:
  env FM_PREPARE_DB_MIGRATION_SNAPSHOTS=force cargo nextest run --workspace --all-targets ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -E 'package({{PACKAGE}})' test_server_db_migrations {{EXTRA_ARGS}}


# regenerate client db migration snapshots
# ex: `just snapshot-client-db-migrations fedimint-dummy-tests`
# ex: `just snapshot-client-db-migrations fedimint-mint-tests`
# ex: `just snapshot-client-db-migrations fedimint-ln-tests`
# ex: `just snapshot-client-db-migrations fedimint-wallet-tests`
snapshot-client-db-migrations PACKAGE *EXTRA_ARGS:
  env FM_PREPARE_DB_MIGRATION_SNAPSHOTS=force cargo nextest run --workspace --all-targets ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -E 'package({{PACKAGE}})' snapshot_client_db_migrations {{EXTRA_ARGS}}
  just test-client-db-migrations {{PACKAGE}} {{EXTRA_ARGS}}

test-client-db-migrations PACKAGE *EXTRA_ARGS:
  env FM_PREPARE_DB_MIGRATION_SNAPSHOTS=force cargo nextest run --workspace --all-targets ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} -E 'package({{PACKAGE}})' test_client_db_migrations {{EXTRA_ARGS}}

test-db-migrations:
  just test-client-db-migrations fedimint-dummy-tests
  just test-client-db-migrations fedimint-mint-tests
  just test-client-db-migrations fedimint-ln-tests
  just test-client-db-migrations fedimint-wallet-tests
  just test-server-db-migrations fedimint-dummy-tests
  just test-server-db-migrations fedimint-mint-tests
  just test-server-db-migrations fedimint-ln-tests
  just test-server-db-migrations fedimint-wallet-tests
  just test-server-db-migrations fedimint-server
  just test-server-db-migrations fedimint-ln-gateway

snapshot-db-migrations:
  just snapshot-client-db-migrations fedimint-dummy-tests
  just snapshot-client-db-migrations fedimint-mint-tests
  just snapshot-client-db-migrations fedimint-ln-tests
  just snapshot-client-db-migrations fedimint-wallet-tests
  just snapshot-server-db-migrations fedimint-dummy-tests
  just snapshot-server-db-migrations fedimint-mint-tests
  just snapshot-server-db-migrations fedimint-ln-tests
  just snapshot-server-db-migrations fedimint-wallet-tests
  just snapshot-server-db-migrations fedimint-server
  just snapshot-server-db-migrations fedimint-ln-gateway
  just test-db-migrations

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

# sign a release (git tag)
sign-release tag:
  ./scripts/release/sign.sh {{tag}}

# benchmark compilation times
bench-compilation:
  ./scripts/bench-compilation.sh

fuzz-target TARGET="" *ARGS="--exit_upon_crash":
  #!/usr/bin/env bash
  set -euo pipefail

  if [ -z "{{TARGET}}" ]; then
    >&2 echo "Available targets:"
    >&2 echo ""
    ls fuzz/src/bin/ | sed -e 's/.rs$//g'
    exit 1
  fi
  # reference: https://github.com/google/honggfuzz/blob/master/docs/USAGE.md#usage
  export HFUZZ_RUN_ARGS="{{ARGS}}"
  # notes:
  # * TODO: make flakebox set CC, as hfuzz seems to ignore CC_<target>
  # * TODO: make flakebox set RUSTFLAGS, as hfuzz seems to ignore CARGO_BUILD_<target>_RUSTFLAGS
  # * can't be run with sccache, so just disable here
  env -u RUSTC_WRAPPER CC=clang RUSTFLAGS="--cfg tokio_unstable" cargo hfuzz run {{TARGET}}

fuzz-target-debug TARGET="" CRASH="" *ARGS="--exit_upon_crash":
  #!/usr/bin/env bash
  set -euo pipefail

  if [ -z "{{TARGET}}" ]; then
    >&2 echo "Available targets:"
    >&2 echo ""
    ls fuzz/src/bin/ | sed -e 's/.rs$//g'
    exit 1
  fi
  # reference: https://github.com/google/honggfuzz/blob/master/docs/USAGE.md#usage
  export HFUZZ_RUN_ARGS="{{ARGS}}"

  export HFUZZ_DEBUGGER=${HFUZZ_DEBUGGER:-gdb}
  crash="CRASH"
  if [ -z "${CRASH:-}" ]; then
    CRASH="hfuzz_workspace/{{TARGET}}/*.fuzz"
  fi
  # notes:
  # * TODO: make flakebox set CC, as hfuzz seems to ignore CC_<target>
  # * TODO: make flakebox set RUSTFLAGS, as hfuzz seems to ignore CARGO_BUILD_<target>_RUSTFLAGS
  # * can't be run with sccache, so just disable here
  env -u RUSTC_WRAPPER CC=clang RUSTFLAGS="--cfg tokio_unstable" cargo hfuzz run-debug {{TARGET}} ${CRASH}
