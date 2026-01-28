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
  ./scripts/dev/test-runner.sh run

# show number of tests per package
test-count:
  ./scripts/tests/test-cov.sh

test-compatibility *VERSIONS="0.8.2 0.9.1 0.10.0":
  ./scripts/dev/test-runner.sh run {{VERSIONS}}

test-full-compatibility *VERSIONS="0.4.4":
  ./scripts/dev/test-runner.sh run --full-matrix {{VERSIONS}}

test-upgrades *VERSIONS="v0.8.2 current, v0.9.1 current, v0.10.0 current":
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
  just test-ci-all
  just test-compatibility
  just udeps

# check before making a release
final-check-release:
  just check-packages-features
  just final-check-ci

# verify verify various feature combinations we might care about
check-packages-features:
  just check-wasm --no-default-features
  # TODO: broken, seems like one of the deps
  # just check-wasm --features iroh
  cargo workspaces exec cargo check
  cargo workspaces exec cargo check --no-default-features
  # there are some features that require nightly
  nix shell github:nix-community/fenix#latest.toolchain -c cargo workspaces exec cargo check --all-features

# like `check-packages-features` but using nix
check-packages-features-using-nix:
  nix build -L .#wasm32-unknown.ci.cargoCheckWasmNoDefaultFeatures
  nix build -L .#ci.cargoWorkspacesCheckNoDefaultFeatures
  nix build -L .#nightly.ci.cargoWorkspacesCheckAllFeatures
  nix build -L .#ci.cargoWorkspacesCheckDefaultFeatures

check-wasm *EXTRA_ARGS:
  #!/usr/bin/env bash
  env CARGO_BUILD_TARGET_DIR=${CARGO_BUILD_TARGET_DIR:-$(pwd)/target}/pkgs/check-wasm \
    nix develop .#crossWasm -c \
      cargo check --target wasm32-unknown-unknown \
        --package fedimint-client \
        --package fedimint-client-wasm \
        --package fedimint-wasm-tests \
        {{EXTRA_ARGS}}

# regenerate server db migration snapshots
# ex: `just snapshot-server-db-migrations fedimint-server`
# ex: `just snapshot-server-db-migrations fedimint-mint-tests`
# ex: `just snapshot-server-db-migrations fedimint-ln-tests`
# ex: `just snapshot-server-db-migrations fedimint-wallet-tests`
# ex: `just snapshot-server-db-migrations fedimint-dummy-tests`
# ex: `just snapshot-server-db-migrations fedimint-gateway-server`
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
  just test-server-db-migrations fedimint-gateway-server

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
  just snapshot-server-db-migrations fedimint-gateway-server
  just test-db-migrations

# start mprocs with a dev federation setup. Default: 4 nodes, add `-n 1` argument to start only 1 node
mprocs *PARAMS:
  ./scripts/dev/mprocs/run.sh {{PARAMS}}

# exit mprocs session
exit-mprocs:
  mprocs --ctl '{c: quit}' --server 127.0.0.1:4050

devimint-env *PARAMS:
  ./scripts/dev/devimint-env.sh {{PARAMS}}

# Spawn devimint pre-dkg on fixed port numbers (useful for UI work)
devimint-env-pre-dkg *PARAMS:
  @>&2 echo "fedimint-0 UI: http://localhost:2002"
  @>&2 echo "fedimint-1 UI: http://localhost:2006"
  @>&2 echo "fedimint-2 UI: http://localhost:2010"
  @>&2 echo "fedimint-3 UI: http://localhost:2014"
  env FM_FEDERATIONS_BASE_PORT=2000 FM_PRE_DKG=true ./scripts/dev/devimint-env.sh {{PARAMS}}

# Spawn devimint post-dkg on fixed port numbers (useful for UI work)
devimint-env-post-dkg *PARAMS:
  @>&2 echo "fedimint-0 UI: http://localhost:2002"
  @>&2 echo "fedimint-1 UI: http://localhost:2006"
  @>&2 echo "fedimint-2 UI: http://localhost:2010"
  @>&2 echo "fedimint-3 UI: http://localhost:2014"
  env FM_FEDERATIONS_BASE_PORT=2000 ./scripts/dev/devimint-env.sh {{PARAMS}}

devimint-env-tmux *PARAMS:
  ./scripts/dev/tmuxinator/run.sh {{PARAMS}}

devimint-env-mprocs *PARAMS:
  ./scripts/dev/mprocs/run.sh {{PARAMS}}

# backport a PR
backport-pr pr:
  nix shell nixpkgs#nodejs -c npx backport --pr-filter {{pr}}

# sign a release (git tag)
sign-release tag:
  ./scripts/release/sign.sh {{tag}}

# benchmark compilation times
bench-compilation:
  ./scripts/bench-compilation.sh

bench-compilation-quick-incr DIR="fedimint-core":
  @env \
    BENCH_COMP_REUSE_TARGET_DIR=1 \
    BENCH_COMP_SKIP_DECORATIONS=1 \
    BENCH_COMP_SKIP_FULL=1 \
    BENCH_COMP_SKIP_COMMAND=build \
    BENCH_COMP_SKIP_PROFILE=release \
    BENCH_COMP_TOUCH_DIR={{DIR}} \
    bash ./scripts/bench-compilation.sh

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
fuzz-ci-quick *ARGS="--exit_upon_crash --run_time 10 -q -v --threads 2":
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

publish-release:
  # We need to add CARGO_PROFILE_DEV_OPT_LEVEL because jemalloc fails to compile on our toolchain without optimizations enabled
  CARGO_PROFILE_DEV_OPT_LEVEL=2 cargo workspaces publish --from-git --allow-dirty

cargo_sort_defaults := "-w -g --order package,features,bin,lib,test,bench,dependencies,dev-dependencies,build-dependencies"
taplo_opts := "-o indent_string=\"    \""

# Fix sort order in `Cargo.toml` files
cargo-sort-fix *ARGS="":
  cargo sort {{cargo_sort_defaults}} {{ARGS}}
  shopt -s globstar && RUST_LOG=taplo=warn taplo fmt {{taplo_opts}} -- **/Cargo.toml

# Check sort order in `Cargo.toml` files
cargo-sort-check *ARGS="":
  cargo sort {{cargo_sort_defaults}} --check {{ARGS}}
  shopt -s globstar && RUST_LOG=taplo=warn taplo fmt {{taplo_opts}} --check -- **/Cargo.toml

# deploy our docker-compose deployment to HOST
deploy-docker-demo HOST:
  #!/usr/bin/env bash

  set -euo pipefail
  cd docker/deploy-fedimintd
  ./deploy.sh {{HOST}}

deploy-docker-demo-all:
  just deploy-docker-demo fedimintd-docker-1.dev.fedimint.org
  just deploy-docker-demo fedimintd-docker-2.dev.fedimint.org
  just deploy-docker-demo fedimintd-docker-3.dev.fedimint.org
  just deploy-docker-demo fedimintd-docker-4.dev.fedimint.org

# Update docs/api.md
ai-generate-api-docs:
  aider \
    --no-auto-commits --no-git \
    --message \
      "Go through API endpoint functions (defined with Rust api_endpoint! macro) and create/update the api.md file documenting the name of the endpoint (resolve the name to value of the constant used), its arguments and return value and the purpose of the API call. When using non-primitive types defined by our project, make the name in the output link to our documentation page for it: 'https://docs.fedimint.org/?search=TypeNameHere'" \
    ./fedimint-core/src/endpoint_constants.rs \
    ./fedimint-server/src/consensus/api.rs \
    ./modules/fedimint-meta-server/src/lib.rs \
    ./modules/fedimint-meta-common/src/endpoint.rs \
    ./modules/fedimint-wallet-server/src/lib.rs \
    ./modules/fedimint-wallet-common/src/endpoint_constants.rs \
    ./modules/fedimint-lnv2-server/src/lib.rs \
    ./modules/fedimint-lnv2-common/src/endpoint_constants.rs \
    ./modules/fedimint-ln-server/src/lib.rs \
    ./modules/fedimint-ln-common/src/gateway_endpoint_constants.rs \
    ./modules/fedimint-ln-common/src/federation_endpoint_constants.rs \
    ./modules/fedimint-mint-server/src/lib.rs \
    ./modules/fedimint-mint-common/src/endpoint_constants.rs \
    docs/api.md
