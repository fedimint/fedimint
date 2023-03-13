default:
  @just --list

# run `cargo build` on everything
build:
  cargo build --all --all-targets

# run `cargo check` on everything
check:
  cargo check --all --all-targets

# run `cargo clippy` on everything
clippy:
  cargo clippy --all --all-targets

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
  ./scripts/rust-tests.sh

# run all tests in parallel like CI would
test-ci-all: 
  ./scripts/test-ci-all.sh

# show number of tests per package
test-count:
  ./scripts/test-cov.sh

# run lints (quick)
lint:
  env NO_STASH=true misc/git-hooks/pre-commit
  just clippy
  env RUSTDOCFLAGS='-D rustdoc::broken_intra_doc_links' cargo doc --profile dev --no-deps --document-private-items

# `cargo udeps` check
udeps:
  nix build -L .#debug.workspaceCargoUdeps

# run all checks recommended before opening a PR
final-check: lint
  cargo test --doc
  just check-wasm
  just test

check-wasm:
  nix develop .#crossWasm -c cargo check --target wasm32-unknown-unknown --package mint-client

# check files you've touched for spelling errors
spell:
  #!/usr/bin/env bash
  >&2 echo '💡 Valid new words can be added to dictionary in `.config/spellcheck.dic`'
  ref_branch=master
  if git rev-parse --verify upstream/master >/dev/null 2>/dev/null ; then
    ref_branch=upstream/master
  elif  git rev-parse --verify upstream/master >/dev/null 2>/dev/null ; then
    ref_branch=u/master
  fi
  cargo spellcheck fix $(git diff $ref_branch..HEAD --name-only)

# try to fix spelling in all files
spell-fix-all:
   @>&2 echo '❗ `cargo spellcheck fix` seems buggy. Quit and verify your changes often.'
   @>&2 echo '💡 Valid new words can be added to dictionary in `.config/spellcheck.dic`'
   cargo spellcheck fix

# run code formatters
format:
  cargo fmt --all
  nixpkgs-fmt $(echo **.nix)

# start tmuxinator with a dev federation setup
tmuxinator:
  ./scripts/tmuxinator.sh
