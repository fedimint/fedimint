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

test-compatibility *VERSIONS="v0.4.4":
  ./scripts/tests/test-ci-all-backcompat.sh {{VERSIONS}}

test-full-compatibility *VERSIONS="v0.2.1":
  env FM_FULL_VERSION_MATRIX=1 ./scripts/tests/test-ci-all-backcompat.sh {{VERSIONS}}

test-upgrades *VERSIONS="v0.3.3 v0.4.0 current":
  ./scripts/tests/upgrade-test.sh {{VERSIONS}}

# `cargo udeps` check
udeps:
  nix build -L .#nightly.test.workspaceCargoUdeps

bench:
  cargo bench

# run all checks recommended before opening a PR
final-check: lint
  # can't use nextest due to: https://github.com/nextest-rs/nextest/issues/16
  cargo test --doc --workspace
  just check-wasm
  just test

# run all/most checks a CI would run
final-check-ci: lint
  just clippy
  just cargo-sort-check
  cargo test --doc --workspace
  just check-wasm
  ./scripts/tests/test-ci-all.sh
  just test-compatibility
  just udeps

check-wasm:
  #!/usr/bin/env bash
  env CARGO_BUILD_TARGET_DIR=${CARGO_BUILD_TARGET_DIR:-$(pwd)/target}/pkgs/check-wasm \
    nix develop .#crossWasm -c \
      cargo check --target wasm32-unknown-unknown \
        --package fedimint-client \
        --package fedimint-wasm-tests

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

devimint-env *PARAMS:
  ./scripts/dev/devimint-env.sh {{PARAMS}}

devimint-env-tmux *PARAMS:
  ./scripts/dev/tmuxinator/run.sh {{PARAMS}}

devimint-env-mprocs *PARAMS:
  ./scripts/dev/mprocs/run.sh {{PARAMS}}

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

# A quick round of fuzzing for every defined target
fuzz-ci-quick *ARGS="--exit_upon_crash --run_time 30 -q -v --threads 2":
  #!/usr/bin/env bash
  set -euo pipefail

  export HFUZZ_RUN_ARGS="{{ARGS}}"
  for target in $(ls fuzz/src/bin/ | sed -e 's/.rs$//g') ; do
    >&2 echo "Fuzzing ${target}"
    env -u RUSTC_WRAPPER CC=clang RUSTFLAGS="--cfg tokio_unstable" \
      cargo hfuzz run "${target}"
  done

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

# Build `cargo doc`-generated documentation
build-docs:
  ./scripts/dev/build-docs.sh

# Build `cargo doc`-generated documentation just like on https://docs.fedimint.org
build-docs-nix: build-docs
  nix build -L .#nightly.ci.workspaceDocExport

# Open `cargo doc`-generated documentation
docs: build-docs
  #!/usr/bin/env bash
  if command -v xdg-open 1>/dev/null 2>/dev/null ; then
    open_cmd="xdg-open"
  elif command -v open 1>/dev/null 2>/dev/null ; then
    open_cmd="open"
  else
    >&2 echo "Install xdg-open. Falling back to one from nix"
    open_cmd="nix shell nixpkgs#xdg-utils -c xdg-open"
  fi
  source "scripts/_common.sh"
  main_index_path="${CARGO_BUILD_TARGET_DIR}/doc/index.html"
  fallback_index_path="${CARGO_BUILD_TARGET_DIR}/doc/fedimint_core/index.html"
  if [ -e "$main_index_path" ]; then
    echo "file://$fallback_index_path"
    $open_cmd "$main_index_path" || true
  else
    echo "file://$fallback_index_path"
    $open_cmd "$fallback_index_path" || true
  fi

# Bump all versions
# ex: `just bump-version 0.5.0-alpha 0.5.0-rc.0`
bump-version FROM_VERSION TO_VERSION:
  find . -name 'Cargo.toml' -exec sed -i 's/{{FROM_VERSION}}/{{TO_VERSION}}/g' {} +

cargo_sort_defaults := "-w -g --order package,features,bin,lib,test,bench,dependencies,dev-dependencies,build-dependencies"

# Fix sort order in `Cargo.toml` files
cargo-sort-fix *ARGS="":
  cargo sort {{cargo_sort_defaults}} {{ARGS}}

# Check sort order in `Cargo.toml` files
cargo-sort-check *ARGS="":
  cargo sort {{cargo_sort_defaults}} --check {{ARGS}}
