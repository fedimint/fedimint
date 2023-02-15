default:
  @just --list

check:
  cargo check --all --all-targets

build:
  cargo build --all --all-targets

# check if ulimit is set correctly
check-ulimit:
  #!/usr/bin/env bash
  if [ "$(ulimit -Sn)" -lt "1024" ]; then
      >&2 echo "⚠️  ulimit too small. Run 'ulimit -Sn 1024' to avoid problems running tests"
  fi

test: build check-ulimit
  cargo test

test-real: check-ulimit
  ./scripts/rust-tests.sh

lint:
  env NO_STASH=true misc/git-hooks/pre-commit
  just clippy
  cargo doc --profile dev --no-deps --document-private-items

clippy:
  cargo clippy --all --all-targets

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

format:
  cargo fmt --all
  nixpkgs-fmt $(echo **.nix)

tmuxinator:
  ./scripts/tmuxinator.sh
