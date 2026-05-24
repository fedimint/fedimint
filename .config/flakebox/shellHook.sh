#!/usr/bin/env bash
yesterday=$(date -d "yesterday" +%s)
motd_ts_path=".config/flakebox/tmp/motd"

if [ ! -e "$motd_ts_path" ] || [ "$motd_ts_path" -ot "$yesterday" ]; then
mkdir -p "$(dirname "$motd_ts_path")"
touch "$motd_ts_path"
>&2 echo "🚧 In an enfort to improve documentation, we now require all structs and"
>&2 echo "🚧 and public methods to be documented with a docstring."
>&2 echo "🚧 See https://github.com/fedimint/fedimint/issues/3807"

fi

root="$(git rev-parse --show-toplevel)"
dot_git="$(git rev-parse --git-common-dir)"
if [[ ! -d "${dot_git}/hooks" ]]; then mkdir -p "${dot_git}/hooks"; fi
# fix old bug
rm -f "${dot_git}/hooks/comit-msg"
rm -f "${dot_git}/hooks/commit-msg"
ln -sf "${root}/misc/git-hooks/commit-msg" "${dot_git}/hooks/commit-msg"

root="$(git rev-parse --show-toplevel)"
dot_git="$(git rev-parse --git-common-dir)"
if [[ ! -d "${dot_git}/hooks" ]]; then mkdir -p "${dot_git}/hooks"; fi
# fix old bug
rm -f "${dot_git}/hooks/pre-comit"
rm -f "${dot_git}/hooks/pre-commit"
ln -sf "${root}/misc/git-hooks/pre-commit" "${dot_git}/hooks/pre-commit"

# set template
git config commit.template misc/git-hooks/commit-template.txt

if ! flakebox lint --silent; then
  >&2 echo "ℹ️  Project recommendations detected. Run 'flakebox lint' for more info."
fi

if [[ "$-" == *i* ]] && [[ -t 2 ]]; then
  >&2 echo "💡 Run 'just' for a list of available 'just ...' helper recipes"
fi
